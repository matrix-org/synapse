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

import copy

import mock

from twisted.internet import defer

import synapse.api.errors
import synapse.handlers.e2e_room_keys
import synapse.storage
from synapse.api import errors

from tests import unittest, utils

# sample room_key data for use in the tests
room_keys = {
    "rooms": {
        "!abc:matrix.org": {
            "sessions": {
                "c0ff33": {
                    "first_message_index": 1,
                    "forwarded_count": 1,
                    "is_verified": False,
                    "session_data": "SSBBTSBBIEZJU0gK",
                }
            }
        }
    }
}


class E2eRoomKeysHandlerTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(E2eRoomKeysHandlerTestCase, self).__init__(*args, **kwargs)
        self.hs = None  # type: synapse.server.HomeServer
        self.handler = None  # type: synapse.handlers.e2e_keys.E2eRoomKeysHandler

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield utils.setup_test_homeserver(
            self.addCleanup, handlers=None, replication_layer=mock.Mock()
        )
        self.handler = synapse.handlers.e2e_room_keys.E2eRoomKeysHandler(self.hs)
        self.local_user = "@boris:" + self.hs.hostname

    @defer.inlineCallbacks
    def test_get_missing_current_version_info(self):
        """Check that we get a 404 if we ask for info about the current version
        if there is no version.
        """
        res = None
        try:
            yield self.handler.get_version_info(self.local_user)
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_get_missing_version_info(self):
        """Check that we get a 404 if we ask for info about a specific version
        if it doesn't exist.
        """
        res = None
        try:
            yield self.handler.get_version_info(self.local_user, "bogus_version")
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_create_version(self):
        """Check that we can create and then retrieve versions.
        """
        res = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(res, "1")

        # check we can retrieve it as the current version
        res = yield self.handler.get_version_info(self.local_user)
        self.assertDictEqual(
            res,
            {
                "version": "1",
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "first_version_auth_data",
            },
        )

        # check we can retrieve it as a specific version
        res = yield self.handler.get_version_info(self.local_user, "1")
        self.assertDictEqual(
            res,
            {
                "version": "1",
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "first_version_auth_data",
            },
        )

        # upload a new one...
        res = yield self.handler.create_version(
            self.local_user,
            {
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "second_version_auth_data",
            },
        )
        self.assertEqual(res, "2")

        # check we can retrieve it as the current version
        res = yield self.handler.get_version_info(self.local_user)
        self.assertDictEqual(
            res,
            {
                "version": "2",
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "second_version_auth_data",
            },
        )

    @defer.inlineCallbacks
    def test_update_version(self):
        """Check that we can update versions.
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        res = yield self.handler.update_version(
            self.local_user,
            version,
            {
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "revised_first_version_auth_data",
                "version": version,
            },
        )
        self.assertDictEqual(res, {})

        # check we can retrieve it as the current version
        res = yield self.handler.get_version_info(self.local_user)
        self.assertDictEqual(
            res,
            {
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "revised_first_version_auth_data",
                "version": version,
            },
        )

    @defer.inlineCallbacks
    def test_update_missing_version(self):
        """Check that we get a 404 on updating nonexistent versions
        """
        res = None
        try:
            yield self.handler.update_version(
                self.local_user,
                "1",
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                    "version": "1",
                },
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_update_bad_version(self):
        """Check that we get a 400 if the version in the body is missing or
        doesn't match
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        res = None
        try:
            yield self.handler.update_version(
                self.local_user,
                version,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                },
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 400)

        res = None
        try:
            yield self.handler.update_version(
                self.local_user,
                version,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                    "version": "incorrect",
                },
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 400)

    @defer.inlineCallbacks
    def test_delete_missing_version(self):
        """Check that we get a 404 on deleting nonexistent versions
        """
        res = None
        try:
            yield self.handler.delete_version(self.local_user, "1")
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_delete_missing_current_version(self):
        """Check that we get a 404 on deleting nonexistent current version
        """
        res = None
        try:
            yield self.handler.delete_version(self.local_user)
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_delete_version(self):
        """Check that we can create and then delete versions.
        """
        res = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(res, "1")

        # check we can delete it
        yield self.handler.delete_version(self.local_user, "1")

        # check that it's gone
        res = None
        try:
            yield self.handler.get_version_info(self.local_user, "1")
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_get_missing_backup(self):
        """Check that we get a 404 on querying missing backup
        """
        res = None
        try:
            yield self.handler.get_room_keys(self.local_user, "bogus_version")
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_get_missing_room_keys(self):
        """Check we get an empty response from an empty backup
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        res = yield self.handler.get_room_keys(self.local_user, version)
        self.assertDictEqual(res, {"rooms": {}})

    # TODO: test the locking semantics when uploading room_keys,
    # although this is probably best done in sytest

    @defer.inlineCallbacks
    def test_upload_room_keys_no_versions(self):
        """Check that we get a 404 on uploading keys when no versions are defined
        """
        res = None
        try:
            yield self.handler.upload_room_keys(
                self.local_user, "no_version", room_keys
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_upload_room_keys_bogus_version(self):
        """Check that we get a 404 on uploading keys when an nonexistent version
        is specified
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        res = None
        try:
            yield self.handler.upload_room_keys(
                self.local_user, "bogus_version", room_keys
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 404)

    @defer.inlineCallbacks
    def test_upload_room_keys_wrong_version(self):
        """Check that we get a 403 on uploading keys for an old version
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        version = yield self.handler.create_version(
            self.local_user,
            {
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "second_version_auth_data",
            },
        )
        self.assertEqual(version, "2")

        res = None
        try:
            yield self.handler.upload_room_keys(self.local_user, "1", room_keys)
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 403)

    @defer.inlineCallbacks
    def test_upload_room_keys_insert(self):
        """Check that we can insert and retrieve keys for a session
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        yield self.handler.upload_room_keys(self.local_user, version, room_keys)

        res = yield self.handler.get_room_keys(self.local_user, version)
        self.assertDictEqual(res, room_keys)

        # check getting room_keys for a given room
        res = yield self.handler.get_room_keys(
            self.local_user, version, room_id="!abc:matrix.org"
        )
        self.assertDictEqual(res, room_keys)

        # check getting room_keys for a given session_id
        res = yield self.handler.get_room_keys(
            self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
        )
        self.assertDictEqual(res, room_keys)

    @defer.inlineCallbacks
    def test_upload_room_keys_merge(self):
        """Check that we can upload a new room_key for an existing session and
        have it correctly merged"""
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        yield self.handler.upload_room_keys(self.local_user, version, room_keys)

        new_room_keys = copy.deepcopy(room_keys)
        new_room_key = new_room_keys["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]

        # test that increasing the message_index doesn't replace the existing session
        new_room_key["first_message_index"] = 2
        new_room_key["session_data"] = "new"
        yield self.handler.upload_room_keys(self.local_user, version, new_room_keys)

        res = yield self.handler.get_room_keys(self.local_user, version)
        self.assertEqual(
            res["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]["session_data"],
            "SSBBTSBBIEZJU0gK",
        )

        # test that marking the session as verified however /does/ replace it
        new_room_key["is_verified"] = True
        yield self.handler.upload_room_keys(self.local_user, version, new_room_keys)

        res = yield self.handler.get_room_keys(self.local_user, version)
        self.assertEqual(
            res["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]["session_data"], "new"
        )

        # test that a session with a higher forwarded_count doesn't replace one
        # with a lower forwarding count
        new_room_key["forwarded_count"] = 2
        new_room_key["session_data"] = "other"
        yield self.handler.upload_room_keys(self.local_user, version, new_room_keys)

        res = yield self.handler.get_room_keys(self.local_user, version)
        self.assertEqual(
            res["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]["session_data"], "new"
        )

        # TODO: check edge cases as well as the common variations here

    @defer.inlineCallbacks
    def test_delete_room_keys(self):
        """Check that we can insert and delete keys for a session
        """
        version = yield self.handler.create_version(
            self.local_user,
            {"algorithm": "m.megolm_backup.v1", "auth_data": "first_version_auth_data"},
        )
        self.assertEqual(version, "1")

        # check for bulk-delete
        yield self.handler.upload_room_keys(self.local_user, version, room_keys)
        yield self.handler.delete_room_keys(self.local_user, version)
        res = yield self.handler.get_room_keys(
            self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
        )
        self.assertDictEqual(res, {"rooms": {}})

        # check for bulk-delete per room
        yield self.handler.upload_room_keys(self.local_user, version, room_keys)
        yield self.handler.delete_room_keys(
            self.local_user, version, room_id="!abc:matrix.org"
        )
        res = yield self.handler.get_room_keys(
            self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
        )
        self.assertDictEqual(res, {"rooms": {}})

        # check for bulk-delete per session
        yield self.handler.upload_room_keys(self.local_user, version, room_keys)
        yield self.handler.delete_room_keys(
            self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
        )
        res = yield self.handler.get_room_keys(
            self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
        )
        self.assertDictEqual(res, {"rooms": {}})

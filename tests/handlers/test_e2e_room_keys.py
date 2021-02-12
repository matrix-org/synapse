# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
# Copyright 2019 Matrix.org Foundation C.I.C.
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

from synapse.api.errors import SynapseError

from tests import unittest

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


class E2eRoomKeysHandlerTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        return self.setup_test_homeserver(replication_layer=mock.Mock())

    def prepare(self, reactor, clock, hs):
        self.handler = hs.get_e2e_room_keys_handler()
        self.local_user = "@boris:" + hs.hostname

    def test_get_missing_current_version_info(self):
        """Check that we get a 404 if we ask for info about the current version
        if there is no version.
        """
        e = self.get_failure(
            self.handler.get_version_info(self.local_user), SynapseError
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_get_missing_version_info(self):
        """Check that we get a 404 if we ask for info about a specific version
        if it doesn't exist.
        """
        e = self.get_failure(
            self.handler.get_version_info(self.local_user, "bogus_version"),
            SynapseError,
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_create_version(self):
        """Check that we can create and then retrieve versions."""
        res = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(res, "1")

        # check we can retrieve it as the current version
        res = self.get_success(self.handler.get_version_info(self.local_user))
        version_etag = res["etag"]
        self.assertIsInstance(version_etag, str)
        del res["etag"]
        self.assertDictEqual(
            res,
            {
                "version": "1",
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "first_version_auth_data",
                "count": 0,
            },
        )

        # check we can retrieve it as a specific version
        res = self.get_success(self.handler.get_version_info(self.local_user, "1"))
        self.assertEqual(res["etag"], version_etag)
        del res["etag"]
        self.assertDictEqual(
            res,
            {
                "version": "1",
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "first_version_auth_data",
                "count": 0,
            },
        )

        # upload a new one...
        res = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "second_version_auth_data",
                },
            )
        )
        self.assertEqual(res, "2")

        # check we can retrieve it as the current version
        res = self.get_success(self.handler.get_version_info(self.local_user))
        del res["etag"]
        self.assertDictEqual(
            res,
            {
                "version": "2",
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "second_version_auth_data",
                "count": 0,
            },
        )

    def test_update_version(self):
        """Check that we can update versions."""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        res = self.get_success(
            self.handler.update_version(
                self.local_user,
                version,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                    "version": version,
                },
            )
        )
        self.assertDictEqual(res, {})

        # check we can retrieve it as the current version
        res = self.get_success(self.handler.get_version_info(self.local_user))
        del res["etag"]
        self.assertDictEqual(
            res,
            {
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "revised_first_version_auth_data",
                "version": version,
                "count": 0,
            },
        )

    def test_update_missing_version(self):
        """Check that we get a 404 on updating nonexistent versions"""
        e = self.get_failure(
            self.handler.update_version(
                self.local_user,
                "1",
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                    "version": "1",
                },
            ),
            SynapseError,
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_update_omitted_version(self):
        """Check that the update succeeds if the version is missing from the body"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        self.get_success(
            self.handler.update_version(
                self.local_user,
                version,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                },
            )
        )

        # check we can retrieve it as the current version
        res = self.get_success(self.handler.get_version_info(self.local_user))
        del res["etag"]  # etag is opaque, so don't test its contents
        self.assertDictEqual(
            res,
            {
                "algorithm": "m.megolm_backup.v1",
                "auth_data": "revised_first_version_auth_data",
                "version": version,
                "count": 0,
            },
        )

    def test_update_bad_version(self):
        """Check that we get a 400 if the version in the body doesn't match"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        e = self.get_failure(
            self.handler.update_version(
                self.local_user,
                version,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "revised_first_version_auth_data",
                    "version": "incorrect",
                },
            ),
            SynapseError,
        )
        res = e.value.code
        self.assertEqual(res, 400)

    def test_delete_missing_version(self):
        """Check that we get a 404 on deleting nonexistent versions"""
        e = self.get_failure(
            self.handler.delete_version(self.local_user, "1"), SynapseError
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_delete_missing_current_version(self):
        """Check that we get a 404 on deleting nonexistent current version"""
        e = self.get_failure(self.handler.delete_version(self.local_user), SynapseError)
        res = e.value.code
        self.assertEqual(res, 404)

    def test_delete_version(self):
        """Check that we can create and then delete versions."""
        res = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(res, "1")

        # check we can delete it
        self.get_success(self.handler.delete_version(self.local_user, "1"))

        # check that it's gone
        e = self.get_failure(
            self.handler.get_version_info(self.local_user, "1"), SynapseError
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_get_missing_backup(self):
        """Check that we get a 404 on querying missing backup"""
        e = self.get_failure(
            self.handler.get_room_keys(self.local_user, "bogus_version"), SynapseError
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_get_missing_room_keys(self):
        """Check we get an empty response from an empty backup"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        res = self.get_success(self.handler.get_room_keys(self.local_user, version))
        self.assertDictEqual(res, {"rooms": {}})

    # TODO: test the locking semantics when uploading room_keys,
    # although this is probably best done in sytest

    def test_upload_room_keys_no_versions(self):
        """Check that we get a 404 on uploading keys when no versions are defined"""
        e = self.get_failure(
            self.handler.upload_room_keys(self.local_user, "no_version", room_keys),
            SynapseError,
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_upload_room_keys_bogus_version(self):
        """Check that we get a 404 on uploading keys when an nonexistent version
        is specified
        """
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        e = self.get_failure(
            self.handler.upload_room_keys(self.local_user, "bogus_version", room_keys),
            SynapseError,
        )
        res = e.value.code
        self.assertEqual(res, 404)

    def test_upload_room_keys_wrong_version(self):
        """Check that we get a 403 on uploading keys for an old version"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "second_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "2")

        e = self.get_failure(
            self.handler.upload_room_keys(self.local_user, "1", room_keys), SynapseError
        )
        res = e.value.code
        self.assertEqual(res, 403)

    def test_upload_room_keys_insert(self):
        """Check that we can insert and retrieve keys for a session"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, room_keys)
        )

        res = self.get_success(self.handler.get_room_keys(self.local_user, version))
        self.assertDictEqual(res, room_keys)

        # check getting room_keys for a given room
        res = self.get_success(
            self.handler.get_room_keys(
                self.local_user, version, room_id="!abc:matrix.org"
            )
        )
        self.assertDictEqual(res, room_keys)

        # check getting room_keys for a given session_id
        res = self.get_success(
            self.handler.get_room_keys(
                self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
            )
        )
        self.assertDictEqual(res, room_keys)

    def test_upload_room_keys_merge(self):
        """Check that we can upload a new room_key for an existing session and
        have it correctly merged"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, room_keys)
        )

        # get the etag to compare to future versions
        res = self.get_success(self.handler.get_version_info(self.local_user))
        backup_etag = res["etag"]
        self.assertEqual(res["count"], 1)

        new_room_keys = copy.deepcopy(room_keys)
        new_room_key = new_room_keys["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]

        # test that increasing the message_index doesn't replace the existing session
        new_room_key["first_message_index"] = 2
        new_room_key["session_data"] = "new"
        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, new_room_keys)
        )

        res = self.get_success(self.handler.get_room_keys(self.local_user, version))
        self.assertEqual(
            res["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]["session_data"],
            "SSBBTSBBIEZJU0gK",
        )

        # the etag should be the same since the session did not change
        res = self.get_success(self.handler.get_version_info(self.local_user))
        self.assertEqual(res["etag"], backup_etag)

        # test that marking the session as verified however /does/ replace it
        new_room_key["is_verified"] = True
        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, new_room_keys)
        )

        res = self.get_success(self.handler.get_room_keys(self.local_user, version))
        self.assertEqual(
            res["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]["session_data"], "new"
        )

        # the etag should NOT be equal now, since the key changed
        res = self.get_success(self.handler.get_version_info(self.local_user))
        self.assertNotEqual(res["etag"], backup_etag)
        backup_etag = res["etag"]

        # test that a session with a higher forwarded_count doesn't replace one
        # with a lower forwarding count
        new_room_key["forwarded_count"] = 2
        new_room_key["session_data"] = "other"
        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, new_room_keys)
        )

        res = self.get_success(self.handler.get_room_keys(self.local_user, version))
        self.assertEqual(
            res["rooms"]["!abc:matrix.org"]["sessions"]["c0ff33"]["session_data"], "new"
        )

        # the etag should be the same since the session did not change
        res = self.get_success(self.handler.get_version_info(self.local_user))
        self.assertEqual(res["etag"], backup_etag)

        # TODO: check edge cases as well as the common variations here

    def test_delete_room_keys(self):
        """Check that we can insert and delete keys for a session"""
        version = self.get_success(
            self.handler.create_version(
                self.local_user,
                {
                    "algorithm": "m.megolm_backup.v1",
                    "auth_data": "first_version_auth_data",
                },
            )
        )
        self.assertEqual(version, "1")

        # check for bulk-delete
        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, room_keys)
        )
        self.get_success(self.handler.delete_room_keys(self.local_user, version))
        res = self.get_success(
            self.handler.get_room_keys(
                self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
            )
        )
        self.assertDictEqual(res, {"rooms": {}})

        # check for bulk-delete per room
        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, room_keys)
        )
        self.get_success(
            self.handler.delete_room_keys(
                self.local_user, version, room_id="!abc:matrix.org"
            )
        )
        res = self.get_success(
            self.handler.get_room_keys(
                self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
            )
        )
        self.assertDictEqual(res, {"rooms": {}})

        # check for bulk-delete per session
        self.get_success(
            self.handler.upload_room_keys(self.local_user, version, room_keys)
        )
        self.get_success(
            self.handler.delete_room_keys(
                self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
            )
        )
        res = self.get_success(
            self.handler.get_room_keys(
                self.local_user, version, room_id="!abc:matrix.org", session_id="c0ff33"
            )
        )
        self.assertDictEqual(res, {"rooms": {}})

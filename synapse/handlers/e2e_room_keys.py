# -*- coding: utf-8 -*-
# Copyright 2017, 2018 New Vector Ltd
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

from six import iteritems

from twisted.internet import defer

from synapse.api.errors import (
    Codes,
    NotFoundError,
    RoomKeysVersionError,
    StoreError,
    SynapseError,
)
from synapse.util.async_helpers import Linearizer

logger = logging.getLogger(__name__)


class E2eRoomKeysHandler(object):
    """
    Implements an optional realtime backup mechanism for encrypted E2E megolm room keys.
    This gives a way for users to store and recover their megolm keys if they lose all
    their clients. It should also extend easily to future room key mechanisms.
    The actual payload of the encrypted keys is completely opaque to the handler.
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()

        # Used to lock whenever a client is uploading key data.  This prevents collisions
        # between clients trying to upload the details of a new session, given all
        # clients belonging to a user will receive and try to upload a new session at
        # roughly the same time.  Also used to lock out uploads when the key is being
        # changed.
        self._upload_linearizer = Linearizer("upload_room_keys_lock")

    @defer.inlineCallbacks
    def get_room_keys(self, user_id, version, room_id=None, session_id=None):
        """Bulk get the E2E room keys for a given backup, optionally filtered to a given
        room, or a given session.
        See EndToEndRoomKeyStore.get_e2e_room_keys for full details.

        Args:
            user_id(str): the user whose keys we're getting
            version(str): the version ID of the backup we're getting keys from
            room_id(string): room ID to get keys for, for None to get keys for all rooms
            session_id(string): session ID to get keys for, for None to get keys for all
                sessions
        Raises:
            NotFoundError: if the backup version does not exist
        Returns:
            A deferred list of dicts giving the session_data and message metadata for
            these room keys.
        """

        # we deliberately take the lock to get keys so that changing the version
        # works atomically
        with (yield self._upload_linearizer.queue(user_id)):
            # make sure the backup version exists
            try:
                yield self.store.get_e2e_room_keys_version_info(user_id, version)
            except StoreError as e:
                if e.code == 404:
                    raise NotFoundError("Unknown backup version")
                else:
                    raise

            results = yield self.store.get_e2e_room_keys(
                user_id, version, room_id, session_id
            )

            defer.returnValue(results)

    @defer.inlineCallbacks
    def delete_room_keys(self, user_id, version, room_id=None, session_id=None):
        """Bulk delete the E2E room keys for a given backup, optionally filtered to a given
        room or a given session.
        See EndToEndRoomKeyStore.delete_e2e_room_keys for full details.

        Args:
            user_id(str): the user whose backup we're deleting
            version(str): the version ID of the backup we're deleting
            room_id(string): room ID to delete keys for, for None to delete keys for all
                rooms
            session_id(string): session ID to delete keys for, for None to delete keys
                for all sessions
        Returns:
            A deferred of the deletion transaction
        """

        # lock for consistency with uploading
        with (yield self._upload_linearizer.queue(user_id)):
            yield self.store.delete_e2e_room_keys(user_id, version, room_id, session_id)

    @defer.inlineCallbacks
    def upload_room_keys(self, user_id, version, room_keys):
        """Bulk upload a list of room keys into a given backup version, asserting
        that the given version is the current backup version.  room_keys are merged
        into the current backup as described in RoomKeysServlet.on_PUT().

        Args:
            user_id(str): the user whose backup we're setting
            version(str): the version ID of the backup we're updating
            room_keys(dict): a nested dict describing the room_keys we're setting:

        {
            "rooms": {
                "!abc:matrix.org": {
                    "sessions": {
                        "c0ff33": {
                            "first_message_index": 1,
                            "forwarded_count": 1,
                            "is_verified": false,
                            "session_data": "SSBBTSBBIEZJU0gK"
                        }
                    }
                }
            }
        }

        Raises:
            NotFoundError: if there are no versions defined
            RoomKeysVersionError: if the uploaded version is not the current version
        """

        # TODO: Validate the JSON to make sure it has the right keys.

        # XXX: perhaps we should use a finer grained lock here?
        with (yield self._upload_linearizer.queue(user_id)):

            # Check that the version we're trying to upload is the current version
            try:
                version_info = yield self.store.get_e2e_room_keys_version_info(user_id)
            except StoreError as e:
                if e.code == 404:
                    raise NotFoundError("Version '%s' not found" % (version,))
                else:
                    raise

            if version_info['version'] != version:
                # Check that the version we're trying to upload actually exists
                try:
                    version_info = yield self.store.get_e2e_room_keys_version_info(
                        user_id, version,
                    )
                    # if we get this far, the version must exist
                    raise RoomKeysVersionError(current_version=version_info['version'])
                except StoreError as e:
                    if e.code == 404:
                        raise NotFoundError("Version '%s' not found" % (version,))
                    else:
                        raise

            # go through the room_keys.
            # XXX: this should/could be done concurrently, given we're in a lock.
            for room_id, room in iteritems(room_keys['rooms']):
                for session_id, session in iteritems(room['sessions']):
                    yield self._upload_room_key(
                        user_id, version, room_id, session_id, session
                    )

    @defer.inlineCallbacks
    def _upload_room_key(self, user_id, version, room_id, session_id, room_key):
        """Upload a given room_key for a given room and session into a given
        version of the backup.  Merges the key with any which might already exist.

        Args:
            user_id(str): the user whose backup we're setting
            version(str): the version ID of the backup we're updating
            room_id(str): the ID of the room whose keys we're setting
            session_id(str): the session whose room_key we're setting
            room_key(dict): the room_key being set
        """

        # get the room_key for this particular row
        current_room_key = None
        try:
            current_room_key = yield self.store.get_e2e_room_key(
                user_id, version, room_id, session_id
            )
        except StoreError as e:
            if e.code == 404:
                pass
            else:
                raise

        if self._should_replace_room_key(current_room_key, room_key):
            yield self.store.set_e2e_room_key(
                user_id, version, room_id, session_id, room_key
            )

    @staticmethod
    def _should_replace_room_key(current_room_key, room_key):
        """
        Determine whether to replace a given current_room_key (if any)
        with a newly uploaded room_key backup

        Args:
            current_room_key (dict): Optional, the current room_key dict if any
            room_key (dict): The new room_key dict which may or may not be fit to
                replace the current_room_key

        Returns:
            True if current_room_key should be replaced by room_key in the backup
        """

        if current_room_key:
            # spelt out with if/elifs rather than nested boolean expressions
            # purely for legibility.

            if room_key['is_verified'] and not current_room_key['is_verified']:
                return True
            elif (
                room_key['first_message_index'] <
                current_room_key['first_message_index']
            ):
                return True
            elif room_key['forwarded_count'] < current_room_key['forwarded_count']:
                return True
            else:
                return False
        return True

    @defer.inlineCallbacks
    def create_version(self, user_id, version_info):
        """Create a new backup version.  This automatically becomes the new
        backup version for the user's keys; previous backups will no longer be
        writeable to.

        Args:
            user_id(str): the user whose backup version we're creating
            version_info(dict): metadata about the new version being created

        {
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "dGhpcyBzaG91bGQgYWN0dWFsbHkgYmUgZW5jcnlwdGVkIGpzb24K"
        }

        Returns:
            A deferred of a string that gives the new version number.
        """

        # TODO: Validate the JSON to make sure it has the right keys.

        # lock everyone out until we've switched version
        with (yield self._upload_linearizer.queue(user_id)):
            new_version = yield self.store.create_e2e_room_keys_version(
                user_id, version_info
            )
            defer.returnValue(new_version)

    @defer.inlineCallbacks
    def get_version_info(self, user_id, version=None):
        """Get the info about a given version of the user's backup

        Args:
            user_id(str): the user whose current backup version we're querying
            version(str): Optional; if None gives the most recent version
                otherwise a historical one.
        Raises:
            NotFoundError: if the requested backup version doesn't exist
        Returns:
            A deferred of a info dict that gives the info about the new version.

        {
            "version": "1234",
            "algorithm": "m.megolm_backup.v1",
            "auth_data": "dGhpcyBzaG91bGQgYWN0dWFsbHkgYmUgZW5jcnlwdGVkIGpzb24K"
        }
        """

        with (yield self._upload_linearizer.queue(user_id)):
            try:
                res = yield self.store.get_e2e_room_keys_version_info(user_id, version)
            except StoreError as e:
                if e.code == 404:
                    raise NotFoundError("Unknown backup version")
                else:
                    raise
            defer.returnValue(res)

    @defer.inlineCallbacks
    def delete_version(self, user_id, version=None):
        """Deletes a given version of the user's e2e_room_keys backup

        Args:
            user_id(str): the user whose current backup version we're deleting
            version(str): the version id of the backup being deleted
        Raises:
            NotFoundError: if this backup version doesn't exist
        """

        with (yield self._upload_linearizer.queue(user_id)):
            try:
                yield self.store.delete_e2e_room_keys_version(user_id, version)
            except StoreError as e:
                if e.code == 404:
                    raise NotFoundError("Unknown backup version")
                else:
                    raise

    @defer.inlineCallbacks
    def update_version(self, user_id, version, version_info):
        """Update the info about a given version of the user's backup

        Args:
            user_id(str): the user whose current backup version we're updating
            version(str): the backup version we're updating
            version_info(dict): the new information about the backup
        Raises:
            NotFoundError: if the requested backup version doesn't exist
        Returns:
            A deferred of an empty dict.
        """
        if "version" not in version_info:
            raise SynapseError(
                400,
                "Missing version in body",
                Codes.MISSING_PARAM
            )
        if version_info["version"] != version:
            raise SynapseError(
                400,
                "Version in body does not match",
                Codes.INVALID_PARAM
            )
        with (yield self._upload_linearizer.queue(user_id)):
            try:
                old_info = yield self.store.get_e2e_room_keys_version_info(
                    user_id, version
                )
            except StoreError as e:
                if e.code == 404:
                    raise NotFoundError("Unknown backup version")
                else:
                    raise
            if old_info["algorithm"] != version_info["algorithm"]:
                raise SynapseError(
                    400,
                    "Algorithm does not match",
                    Codes.INVALID_PARAM
                )

            yield self.store.update_e2e_room_keys_version(user_id, version, version_info)

            defer.returnValue({})

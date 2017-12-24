# -*- coding: utf-8 -*-
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

import logging

from twisted.internet import defer

from synapse.api.errors import StoreError, SynapseError, RoomKeysVersionError
from synapse.util.async import Linearizer

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
    def get_room_keys(self, user_id, version, room_id, session_id):
        # we deliberately take the lock to get keys so that changing the version
        # works atomically
        with (yield self._upload_linearizer.queue(user_id)):
            results = yield self.store.get_e2e_room_keys(
                user_id, version, room_id, session_id
            )
            defer.returnValue(results)

    @defer.inlineCallbacks
    def delete_room_keys(self, user_id, version, room_id, session_id):
        # lock for consistency with uploading
        with (yield self._upload_linearizer.queue(user_id)):
            yield self.store.delete_e2e_room_keys(user_id, version, room_id, session_id)

    @defer.inlineCallbacks
    def upload_room_keys(self, user_id, version, room_keys):

        # TODO: Validate the JSON to make sure it has the right keys.

        # XXX: perhaps we should use a finer grained lock here?
        with (yield self._upload_linearizer.queue(user_id)):
            # Check that the version we're trying to upload is the current version
            try:
                version_info = yield self.get_version_info(user_id, version)
            except StoreError as e:
                if e.code == 404:
                    raise SynapseError(404, "Version '%s' not found" % (version,))
                else:
                    raise e

            if version_info['version'] != version:
                raise RoomKeysVersionError(current_version=version_info.version)

            # go through the room_keys.
            # XXX: this should/could be done concurrently, given we're in a lock.
            for room_id, room in room_keys['rooms'].iteritems():
                for session_id, session in room['sessions'].iteritems():
                    room_key = session[session_id]

                    yield self._upload_room_key(
                        user_id, version, room_id, session_id, room_key
                    )

    @defer.inlineCallbacks
    def _upload_room_key(self, user_id, version, room_id, session_id, room_key):
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
                raise e

        if E2eRoomKeysHandler._should_replace_room_key(current_room_key, room_key):
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
                pass
            elif (
                room_key['first_message_index'] <
                current_room_key['first_message_index']
            ):
                pass
            elif room_key['forwarded_count'] < current_room_key['forwarded_count']:
                pass
            else:
                return False
        return True

    @defer.inlineCallbacks
    def create_version(self, user_id, version_info):

        # TODO: Validate the JSON to make sure it has the right keys.

        # lock everyone out until we've switched version
        with (yield self._upload_linearizer.queue(user_id)):
            new_version = yield self.store.create_e2e_room_keys_version(
                user_id, version_info
            )
            defer.returnValue(new_version)

    @defer.inlineCallbacks
    def get_version_info(self, user_id, version):
        with (yield self._upload_linearizer.queue(user_id)):
            results = yield self.store.get_e2e_room_keys_version_info(
                user_id, version
            )
            defer.returnValue(results)

    @defer.inlineCallbacks
    def delete_version(self, user_id, version):
        with (yield self._upload_linearizer.queue(user_id)):
            yield self.store.delete_e2e_room_keys_version(user_id, version)

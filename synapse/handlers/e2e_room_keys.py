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

from synapse.api.errors import StoreError
from synapse.util.async import Linearizer

logger = logging.getLogger(__name__)


class E2eRoomKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self._upload_linearizer = Linearizer("upload_room_keys_lock")

    @defer.inlineCallbacks
    def get_room_keys(self, user_id, version, room_id, session_id):
        results = yield self.store.get_e2e_room_keys(
            user_id, version, room_id, session_id
        )
        defer.returnValue(results)

    @defer.inlineCallbacks
    def delete_room_keys(self, user_id, version, room_id, session_id):
        yield self.store.delete_e2e_room_keys(user_id, version, room_id, session_id)

    @defer.inlineCallbacks
    def upload_room_keys(self, user_id, version, room_keys):

        # TODO: Validate the JSON to make sure it has the right keys.

        # XXX: perhaps we should use a finer grained lock here?
        with (yield self._upload_linearizer.queue(user_id)):

            # go through the room_keys
            for room_id in room_keys['rooms']:
                for session_id in room_keys['rooms'][room_id]['sessions']:
                    room_key = room_keys['rooms'][room_id]['sessions'][session_id]

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
                raise

        # check whether we merge or not. spelling it out with if/elifs rather
        # than lots of booleans for legibility.
        upsert = True
        if current_room_key:
            if room_key['is_verified'] and not current_room_key['is_verified']:
                pass
            elif (
                room_key['first_message_index'] <
                current_room_key['first_message_index']
            ):
                pass
            elif room_key['forwarded_count'] < room_key['forwarded_count']:
                pass
            else:
                upsert = False

        # if so, we set the new room_key
        if upsert:
            yield self.store.set_e2e_room_key(
                user_id, version, room_id, session_id, room_key
            )

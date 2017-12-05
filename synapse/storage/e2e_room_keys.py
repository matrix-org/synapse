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

from twisted.internet import defer

from synapse.util.caches.descriptors import cached

from canonicaljson import encode_canonical_json
import ujson as json

from ._base import SQLBaseStore


class EndToEndRoomKeyStore(SQLBaseStore):

    @defer.inlineCallbacks
    def get_e2e_room_key(self, user_id, version, room_id, session_id):

        row = yield self._simple_select_one(
            table="e2e_room_keys",
            keyvalues={
                "user_id": user_id,
                "version": version,
                "room_id": room_id,
                "session_id": session_id,
            },
            retcols=(
                "first_message_index",
                "forwarded_count",
                "is_verified",
                "session_data",
            ),
            desc="get_e2e_room_key",
        )

        defer.returnValue(row);

    def set_e2e_room_key(self, user_id, version, room_id, session_id, room_key):

        def _set_e2e_room_key_txn(txn):

            self._simple_upsert(
                txn,
                table="e2e_room_keys",
                keyvalues={
                    "user_id": user_id,
                    "room_id": room_id,
                    "session_id": session_id,   
                }
                values=[
                    {
                        "version": version,
                        "first_message_index": room_key['first_message_index'],
                        "forwarded_count": room_key['forwarded_count'],
                        "is_verified": room_key['is_verified'],
                        "session_data": room_key['session_data'],
                    }
                ],
                lock=False,
            )

            return True

        return self.runInteraction(
            "set_e2e_room_key", _set_e2e_room_key_txn
        )


    # XXX: this isn't currently used and isn't tested anywhere
    # it could be used in future for bulk-uploading new versions of room_keys
    # for a user or something though.
    def set_e2e_room_keys(self, user_id, version, room_keys):

        def _set_e2e_room_keys_txn(txn):

            self._simple_insert_many_txn(
                txn,
                table="e2e_room_keys",
                values=[
                    {
                        "user_id": user_id,
                        "room_id": room_id,
                        "session_id": session_id,
                        "version": version,
                        "first_message_index": room_keys['rooms'][room_id]['sessions'][session_id]['first_message_index'],
                        "forwarded_count": room_keys['rooms'][room_id]['sessions'][session_id]['forwarded_count'],
                        "is_verified": room_keys['rooms'][room_id]['sessions'][session_id]['is_verified'],
                        "session_data": room_keys['rooms'][room_id]['sessions'][session_id]['session_data'],
                    }
                    for session_id in room_keys['rooms'][room_id]['sessions']
                    for room_id in room_keys['rooms']
                ]
            )

            return True

        return self.runInteraction(
            "set_e2e_room_keys", _set_e2e_room_keys_txn
        )

    @defer.inlineCallbacks
    def get_e2e_room_keys(self, user_id, version, room_id, session_id):

        keyvalues={
            "user_id": user_id,
            "version": version,
        }
        if room_id: keyvalues['room_id'] = room_id
        if session_id: keyvalues['session_id'] = session_id

        rows = yield self._simple_select_list(
            table="e2e_room_keys",
            keyvalues=keyvalues,
            retcols=(
                "first_message_index",
                "forwarded_count",
                "is_verified",
                "session_data",
            ),
            desc="get_e2e_room_keys",
        )

        sessions = {}
        sessions['rooms'][roomId]['sessions'][session_id] = row for row in rows;
        defer.returnValue(sessions);

    @defer.inlineCallbacks
    def delete_e2e_room_keys(self, user_id, version, room_id, session_id):

        keyvalues={
            "user_id": user_id,
            "version": version,
        }
        if room_id: keyvalues['room_id'] = room_id
        if session_id: keyvalues['session_id'] = session_id

        yield self._simple_delete(
            table="e2e_room_keys",
            keyvalues=keyvalues,
            desc="delete_e2e_room_keys",
        )

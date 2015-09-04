# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.storage._base import SQLBaseStore


class PendingInvitesStore(SQLBaseStore):
    def __init__(self, hs):
        super(PendingInvitesStore, self).__init__(hs)

    @defer.inlineCallbacks
    def store_pending_invitation(self, nonce, room_id, inviting_user_id, token_id):
        """
        Stores that a 3pid should be invited to a room when it can be resolved
        to a Matrix ID.

        Args:
            nonce (str): A unique identifying token.
            room_id (str): The room to which the 3pid should be invited.
            inviting_user_id (str): The user who invited the 3pid.
            token_id (int): The access token with which the invite was created.
        """
        next_id = yield self._pending_invites_id_gen.get_next()

        def f(txn):
            query = (
                "INSERT INTO pending_invites"
                " (id, nonce, room_id, inviting_user_id, token_id)"
                " VALUES (?, ?, ?, ?, ?)"
            )
            txn.execute(
                query,
                (next_id, nonce, room_id, inviting_user_id, token_id,)
            )

        yield self.runInteraction("store_pending_invitation", f)

    @defer.inlineCallbacks
    def get_and_delete_pending_invitation_by_nonce(self, nonce):
        """Look up a pending invitation by nonce.

        This method deletes the record of the invitation from the database, and
        hands responsibility for following up (e.g. with an invite) to the caller.

        Args:
            nonce (str): The unique identifying token.

        Returns:
            A dict containing the following keys:
                room_id (str): The room to which the 3pid should be invited.
                inviting_user_id (str): The user who invited the 3pid.
                token_id (int): The access token with which the invite was created.
        """
        def f(txn):
            sql = (
                "SELECT room_id, inviting_user_id, token_id"
                " FROM pending_invites"
                " WHERE nonce = ?"
            )
            txn.execute(sql, (nonce,))
            rows = self.cursor_to_dict(txn)

            sql = "DELETE FROM pending_invites WHERE nonce = ?"
            txn.execute(sql, (nonce,))

            if rows:
                return rows[0]
            return None

        val = yield self.runInteraction("get_pending_invitation_by_nonce", f)
        defer.returnValue(val)

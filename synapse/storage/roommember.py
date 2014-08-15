# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from synapse.types import UserID
from synapse.api.constants import Membership
from synapse.api.events.room import RoomMemberEvent

from ._base import SQLBaseStore, Table


import collections
import json
import logging

logger = logging.getLogger(__name__)


class RoomMemberStore(SQLBaseStore):

    @defer.inlineCallbacks
    def _store_room_member(self, event):
        """Store a room member in the database.
        """
        domain = self.hs.parse_userid(event.target_user_id).domain

        yield self._simple_insert(
            "room_memberships",
            {
                "event_id": event.event_id,
                "user_id": event.target_user_id,
                "sender": event.user_id,
                "room_id": event.room_id,
                "membership": event.membership,
            }
        )

        # Update room hosts table
        if event.membership == Membership.JOIN:
            sql = (
                "INSERT OR IGNORE INTO room_hosts (room_id, host) "
                "VALUES (?, ?)"
            )
            yield self._execute(None, sql, event.room_id, domain)
        else:
            sql = (
                "DELETE FROM room_hosts WHERE room_id = ? AND host = ?"
            )

            yield self._execute(None, sql, event.room_id, domain)


    @defer.inlineCallbacks
    def get_room_member(self, user_id, room_id):
        """Retrieve the current state of a room member.

        Args:
            user_id (str): The member's user ID.
            room_id (str): The room the member is in.
        Returns:
            Deferred: Results in a MembershipEvent or None.
        """
        rows = yield self._get_members_by_dict({
            "e.room_id": room_id,
            "m.user_id": user_id,
        })

        defer.returnValue(rows[0] if rows else None)

    def get_room_members(self, room_id, membership=None):
        """Retrieve the current room member list for a room.

        Args:
            room_id (str): The room to get the list of members.
            membership (synapse.api.constants.Membership): The filter to apply
            to this list, or None to return all members with some state
            associated with this room.
        Returns:
            list of namedtuples representing the members in this room.
        """

        where = {"m.room_id": room_id}
        if membership:
            where["m.membership"] = membership

        return self._get_members_by_dict(where)

    def get_rooms_for_user_where_membership_is(self, user_id, membership_list):
        """ Get all the rooms for this user where the membership for this user
        matches one in the membership list.

        Args:
            user_id (str): The user ID.
            membership_list (list): A list of synapse.api.constants.Membership
            values which the user must be in.
        Returns:
            A list of dicts with "room_id" and "membership" keys.
        """
        if not membership_list:
            return defer.succeed(None)

        args = [user_id]
        args.extend(membership_list)

        where_clause = "user_id = ? AND (%s)" % (
            " OR ".join(["membership = ?" for _ in membership_list]),
        )

        return self._get_members_query(where_clause, args)

    def get_joined_hosts_for_room(self, room_id):
        return self._simple_select_onecol(
            "room_hosts",
            {"room_id": room_id},
            "host"
        )

    def _get_members_by_dict(self, where_dict):
        clause = " AND ".join("%s = ?" % k for k in where_dict.keys())
        vals = where_dict.values()
        return self._get_members_query(clause, vals)

    @defer.inlineCallbacks
    def _get_members_query(self, where_clause, where_values):
        sql = (
            "SELECT e.* FROM events as e "
            "INNER JOIN room_memberships as m "
            "ON e.event_id = m.event_id "
            "INNER JOIN current_state_events as c "
            "ON m.event_id = c.event_id "
            "WHERE %s "
        ) % (where_clause,)

        rows = yield self._execute_and_decode(sql, *where_values)

        logger.debug("_get_members_query Got rows %s", rows)

        results = [self._parse_event_from_row(r) for r in rows]
        defer.returnValue(results)

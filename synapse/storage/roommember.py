# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from collections import namedtuple

from ._base import SQLBaseStore, cached

from synapse.api.constants import Membership
from synapse.types import UserID

import logging

logger = logging.getLogger(__name__)


RoomsForUser = namedtuple(
    "RoomsForUser",
    ("room_id", "sender", "membership")
)


class RoomMemberStore(SQLBaseStore):

    def _store_room_member_txn(self, txn, event):
        """Store a room member in the database.
        """
        try:
            target_user_id = event.state_key
        except:
            logger.exception(
                "Failed to parse target_user_id=%s", target_user_id
            )
            raise

        logger.debug(
            "_store_room_member_txn: target_user_id=%s, membership=%s",
            target_user_id,
            event.membership,
        )

        self._simple_insert_txn(
            txn,
            "room_memberships",
            {
                "event_id": event.event_id,
                "user_id": target_user_id,
                "sender": event.user_id,
                "room_id": event.room_id,
                "membership": event.membership,
            }
        )

        self.get_rooms_for_user.invalidate(target_user_id)
        self.get_joined_hosts_for_room.invalidate(event.room_id)

    def get_room_member(self, user_id, room_id):
        """Retrieve the current state of a room member.

        Args:
            user_id (str): The member's user ID.
            room_id (str): The room the member is in.
        Returns:
            Deferred: Results in a MembershipEvent or None.
        """
        def f(txn):
            events = self._get_members_events_txn(
                txn,
                room_id,
                user_id=user_id,
            )

            return events[0] if events else None

        return self.runInteraction("get_room_member", f)

    def get_users_in_room(self, room_id):
        def f(txn):

            rows = self._get_members_rows_txn(
                txn,
                room_id=room_id,
                membership=Membership.JOIN,
            )

            return [r["user_id"] for r in rows]
        return self.runInteraction("get_users_in_room", f)

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

        def f(txn):
            return self._get_members_events_txn(
                txn,
                room_id,
                membership=membership,
            )

        return self.runInteraction("get_room_members", f)

    def get_rooms_for_user_where_membership_is(self, user_id, membership_list):
        """ Get all the rooms for this user where the membership for this user
        matches one in the membership list.

        Args:
            user_id (str): The user ID.
            membership_list (list): A list of synapse.api.constants.Membership
            values which the user must be in.
        Returns:
            A list of dictionary objects, with room_id, membership and sender
            defined.
        """
        if not membership_list:
            return defer.succeed(None)

        return self.runInteraction(
            "get_rooms_for_user_where_membership_is",
            self._get_rooms_for_user_where_membership_is_txn,
            user_id, membership_list
        )

    def _get_rooms_for_user_where_membership_is_txn(self, txn, user_id,
                                                    membership_list):
        where_clause = "user_id = ? AND (%s)" % (
            " OR ".join(["membership = ?" for _ in membership_list]),
        )

        args = [user_id]
        args.extend(membership_list)

        sql = (
            "SELECT m.room_id, m.sender, m.membership"
            " FROM room_memberships as m"
            " INNER JOIN current_state_events as c"
            " ON m.event_id = c.event_id "
            " AND m.room_id = c.room_id "
            " AND m.user_id = c.state_key"
            " WHERE %s"
        ) % (where_clause,)

        txn.execute(sql, args)
        return [
            RoomsForUser(**r) for r in self.cursor_to_dict(txn)
        ]

    @cached()
    def get_joined_hosts_for_room(self, room_id):
        return self.runInteraction(
            "get_joined_hosts_for_room",
            self._get_joined_hosts_for_room_txn,
            room_id,
        )

    def _get_joined_hosts_for_room_txn(self, txn, room_id):
        rows = self._get_members_rows_txn(
            txn,
            room_id, membership=Membership.JOIN
        )

        joined_domains = set(
            UserID.from_string(r["user_id"]).domain
            for r in rows
        )

        return joined_domains

    def _get_members_query(self, where_clause, where_values):
        return self.runInteraction(
            "get_members_query", self._get_members_events_txn,
            where_clause, where_values
        )

    def _get_members_events_txn(self, txn, room_id, membership=None, user_id=None):
        rows = self._get_members_rows_txn(
            txn,
            room_id, membership, user_id,
        )
        return self._get_events_txn(txn, [r["event_id"] for r in rows])

    def _get_members_rows_txn(self, txn, room_id, membership=None, user_id=None):
        where_clause = "c.room_id = ?"
        where_values = [room_id]

        if membership:
            where_clause += " AND m.membership = ?"
            where_values.append(membership)

        if user_id:
            where_clause += " AND m.user_id = ?"
            where_values.append(user_id)

        sql = (
            "SELECT m.* FROM room_memberships as m"
            " INNER JOIN current_state_events as c"
            " ON m.event_id = c.event_id "
            " AND m.room_id = c.room_id "
            " AND m.user_id = c.state_key"
            " WHERE %(where)s"
        ) % {
            "where": where_clause,
        }

        txn.execute(sql, where_values)
        rows = self.cursor_to_dict(txn)

        return rows

    @cached()
    def get_rooms_for_user(self, user_id):
        return self.get_rooms_for_user_where_membership_is(
            user_id, membership_list=[Membership.JOIN],
        )

    @defer.inlineCallbacks
    def user_rooms_intersect(self, user_id_list):
        """ Checks whether all the users whose IDs are given in a list share a
        room.

        This is a "hot path" function that's called a lot, e.g. by presence for
        generating the event stream. As such, it is implemented locally by
        wrapping logic around heavily-cached database queries.
        """
        if len(user_id_list) < 2:
            defer.returnValue(True)

        deferreds = [self.get_rooms_for_user(u) for u in user_id_list]

        results = yield defer.DeferredList(deferreds, consumeErrors=True)

        # A list of sets of strings giving room IDs for each user
        room_id_lists = [set([r.room_id for r in result[1]]) for result in results]

        # There isn't a setintersection(*list_of_sets)
        ret = len(room_id_lists.pop(0).intersection(*room_id_lists)) > 0

        defer.returnValue(ret)

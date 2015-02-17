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

from ._base import SQLBaseStore

from synapse.api.constants import Membership
from synapse.types import UserID

import logging

logger = logging.getLogger(__name__)


RoomsForUser = namedtuple(
    "RoomsForUser",
    ("room_id", "sender", "membership")
)


class RoomMemberStore(SQLBaseStore):

    def __init__(self, *args, **kw):
        super(RoomMemberStore, self).__init__(*args, **kw)

        self._user_rooms_cache = {}

    def _store_room_member_txn(self, txn, event):
        """Store a room member in the database.
        """
        try:
            target_user_id = event.state_key
            domain = UserID.from_string(target_user_id).domain
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

        # Update room hosts table
        if event.membership == Membership.JOIN:
            sql = (
                "INSERT OR IGNORE INTO room_hosts (room_id, host) "
                "VALUES (?, ?)"
            )
            txn.execute(sql, (event.room_id, domain))
        elif event.membership != Membership.INVITE:
            # Check if this was the last person to have left.
            member_events = self._get_members_query_txn(
                txn,
                where_clause=("c.room_id = ? AND m.membership = ?"
                              " AND m.user_id != ?"),
                where_values=(event.room_id, Membership.JOIN, target_user_id,)
            )

            joined_domains = set()
            for e in member_events:
                try:
                    joined_domains.add(
                        UserID.from_string(e.state_key).domain
                    )
                except:
                    # FIXME: How do we deal with invalid user ids in the db?
                    logger.exception("Invalid user_id: %s", event.state_key)

            if domain not in joined_domains:
                sql = (
                    "DELETE FROM room_hosts WHERE room_id = ? AND host = ?"
                )

                txn.execute(sql, (event.room_id, domain))

        self.invalidate_rooms_for_user(target_user_id)

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

    def _get_room_member(self, txn, user_id, room_id):
        sql = (
            "SELECT e.* FROM events as e"
            " INNER JOIN room_memberships as m"
            " ON e.event_id = m.event_id"
            " INNER JOIN current_state_events as c"
            " ON m.event_id = c.event_id"
            " WHERE m.user_id = ? and e.room_id = ?"
            " LIMIT 1"
        )
        txn.execute(sql, (user_id, room_id))
        rows = self.cursor_to_dict(txn)
        if rows:
            return self._parse_events_txn(txn, rows)[0]
        else:
            return None

    def get_users_in_room(self, room_id):
        def f(txn):
            sql = (
                "SELECT m.user_id FROM room_memberships as m"
                " INNER JOIN current_state_events as c"
                " ON m.event_id = c.event_id"
                " WHERE m.membership = ? AND m.room_id = ?"
            )

            txn.execute(sql, (Membership.JOIN, room_id))
            return [r[0] for r in txn.fetchall()]
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
            A list of dictionary objects, with room_id, membership and sender
            defined.
        """
        if not membership_list:
            return defer.succeed(None)

        where_clause = "user_id = ? AND (%s)" % (
            " OR ".join(["membership = ?" for _ in membership_list]),
        )

        args = [user_id]
        args.extend(membership_list)

        def f(txn):
            sql = (
                "SELECT m.room_id, m.sender, m.membership"
                " FROM room_memberships as m"
                " INNER JOIN current_state_events as c"
                " ON m.event_id = c.event_id"
                " WHERE %s"
            ) % (where_clause,)

            txn.execute(sql, args)
            return [
                RoomsForUser(**r) for r in self.cursor_to_dict(txn)
            ]

        return self.runInteraction(
            "get_rooms_for_user_where_membership_is",
            f
        )

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

    def _get_members_query(self, where_clause, where_values):
        return self.runInteraction(
            "get_members_query", self._get_members_query_txn,
            where_clause, where_values
        )

    def _get_members_query_txn(self, txn, where_clause, where_values):
        sql = (
            "SELECT e.* FROM events as e "
            "INNER JOIN room_memberships as m "
            "ON e.event_id = m.event_id "
            "INNER JOIN current_state_events as c "
            "ON m.event_id = c.event_id "
            "WHERE %(where)s "
        ) % {
            "where": where_clause,
        }

        txn.execute(sql, where_values)
        rows = self.cursor_to_dict(txn)

        results = self._parse_events_txn(txn, rows)
        return results

    # TODO(paul): Create a nice @cached decorator to do this
    #    @cached
    #    def get_foo(...)
    #        ...
    #    invalidate_foo = get_foo.invalidator

    @defer.inlineCallbacks
    def get_rooms_for_user(self, user_id):
        # TODO(paul): put some performance counters in here so we can easily
        #   track what impact this cache is having
        if user_id in self._user_rooms_cache:
            defer.returnValue(self._user_rooms_cache[user_id])

        rooms = yield self.get_rooms_for_user_where_membership_is(
            user_id, membership_list=[Membership.JOIN],
        )

        # TODO(paul): Consider applying a maximum size; just evict things at
        #   random, or consider LRU?

        self._user_rooms_cache[user_id] = rooms
        defer.returnValue(rooms)

    def invalidate_rooms_for_user(self, user_id):
        if user_id in self._user_rooms_cache:
            del self._user_rooms_cache[user_id]

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

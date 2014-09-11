# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from ._base import SQLBaseStore

from synapse.api.constants import Membership

import logging

logger = logging.getLogger(__name__)


class RoomMemberStore(SQLBaseStore):

    def _store_room_member_from_event_txn(self, txn, event):
        self._store_room_member_txn(txn,
            target_user_id=event.state_key,
            sender_user_id=event.user_id,
            room_id=event.room_id,
            event_id=event.event_id,
            membership=event.membership,
        )

    def _store_room_member_txn(self, txn, target_user_id, sender_user_id,
            room_id, event_id, membership):
        """Store a room member in the database.
        """
        domain = self.hs.parse_userid(target_user_id).domain

        self._simple_insert_txn(
            txn,
            "room_memberships",
            {
                "event_id": event_id,
                "user_id": target_user_id,
                "sender": sender_user_id,
                "room_id": room_id,
                "membership": membership,
            }
        )

        # Update room hosts table
        # TODO(paul): This code is massively broken currently as it doesn't
        #   count users per room - meaning it'll delete on the FIRST user to
        #   have a membership other than JOIN - say, LEAVE, or even INVITE.
        # FIXME
        if membership == Membership.JOIN:
            sql = (
                "INSERT OR IGNORE INTO room_hosts (room_id, host) "
                "VALUES (?, ?)"
            )
            txn.execute(sql, (room_id, domain))
        else:
            sql = (
                "DELETE FROM room_hosts WHERE room_id = ? AND host = ?"
            )

            txn.execute(sql, (room_id, domain))

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

        # logger.debug("_get_members_query Got rows %s", rows)

        results = yield self._parse_events(rows)
        defer.returnValue(results)

    @defer.inlineCallbacks
    def user_rooms_intersect(self, user_list):
        """ Checks whether a list of users share a room.
        """
        user_list_clause = " OR ".join(["m.user_id = ?"] * len(user_list))
        sql = (
            "SELECT m.room_id FROM room_memberships as m "
            "INNER JOIN current_state_events as c "
            "ON m.event_id = c.event_id "
            "WHERE m.membership = 'join' "
            "AND (%(clause)s) "
            "GROUP BY m.room_id HAVING COUNT(m.room_id) = ?"
        ) % {"clause": user_list_clause}

        args = user_list
        args.append(len(user_list))

        rows = yield self._execute(None, sql, *args)

        defer.returnValue(len(rows) > 0)

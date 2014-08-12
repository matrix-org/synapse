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

    def get_room_member(self, user_id, room_id):
        """Retrieve the current state of a room member.

        Args:
            user_id (str): The member's user ID.
            room_id (str): The room the member is in.
        Returns:
            namedtuple: The room member from the database, or None if this
            member does not exist.
        """
        query = RoomMemberTable.select_statement(
            "room_id = ? AND user_id = ? ORDER BY id DESC LIMIT 1")
        return self._execute(
            RoomMemberTable.decode_single_result,
            query, room_id, user_id,
        )

    def store_room_member(self, user_id, sender, room_id, membership, content):
        """Store a room member in the database.

        Args:
            user_id (str): The member's user ID.
            room_id (str): The room in relation to the member.
            membership (synapse.api.constants.Membership): The new membership
            state.
            content (dict): The content of the membership (JSON).
        """
        content_json = json.dumps(content)
        return self._simple_insert(RoomMemberTable.table_name, dict(
            user_id=user_id,
            sender=sender,
            room_id=room_id,
            membership=membership,
            content=content_json,
        ))

    @defer.inlineCallbacks
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
        query = RoomMemberTable.select_statement(
            "id IN (SELECT MAX(id) FROM " + RoomMemberTable.table_name
            + " WHERE room_id = ? GROUP BY user_id)"
        )
        res = yield self._execute(
            RoomMemberTable.decode_results, query, room_id,
        )
        # strip memberships which don't match
        if membership:
            res = [entry for entry in res if entry.membership == membership]
        defer.returnValue(res)

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
        membership_placeholder = ["membership=?"] * len(membership_list)
        where_membership = "(" + " OR ".join(membership_placeholder) + ")"
        for membership in membership_list:
            args.append(membership)

        query = ("SELECT room_id, membership FROM room_memberships"
                 + " WHERE user_id=? AND " + where_membership
                 + " GROUP BY room_id ORDER BY id DESC")
        return self._execute(
            self.cursor_to_dict, query, *args
        )

    @defer.inlineCallbacks
    def get_joined_hosts_for_room(self, room_id):
        query = RoomMemberTable.select_statement(
            "id IN (SELECT MAX(id) FROM " + RoomMemberTable.table_name
            + " WHERE room_id = ? GROUP BY user_id)"
        )

        res = yield self._execute(
            RoomMemberTable.decode_results, query, room_id,
        )

        def host_from_user_id_string(user_id):
            domain = UserID.from_string(entry.user_id, self.hs).domain
            return domain

        # strip memberships which don't match
        hosts = [
            host_from_user_id_string(entry.user_id)
            for entry in res
            if entry.membership == Membership.JOIN
        ]

        logger.debug("Returning hosts: %s from results: %s", hosts, res)

        defer.returnValue(hosts)

    def get_max_room_member_id(self):
        return self._simple_max_id(RoomMemberTable.table_name)


class RoomMemberTable(Table):
    table_name = "room_memberships"

    fields = [
        "id",
        "user_id",
        "sender",
        "room_id",
        "membership",
        "content"
    ]

    class EntryType(collections.namedtuple("RoomMemberEntry", fields)):

        def as_event(self, event_factory):
            return event_factory.create_event(
                etype=RoomMemberEvent.TYPE,
                room_id=self.room_id,
                target_user_id=self.user_id,
                user_id=self.sender,
                content=json.loads(self.content),
            )

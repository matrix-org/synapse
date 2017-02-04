# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks

from synapse.api.constants import Membership, EventTypes
from synapse.types import get_domain_from_id

import logging
import ujson as json

logger = logging.getLogger(__name__)


RoomsForUser = namedtuple(
    "RoomsForUser",
    ("room_id", "sender", "membership", "event_id", "stream_ordering")
)


_MEMBERSHIP_PROFILE_UPDATE_NAME = "room_membership_profile_update"


class RoomMemberStore(SQLBaseStore):
    def __init__(self, hs):
        super(RoomMemberStore, self).__init__(hs)
        self.register_background_update_handler(
            _MEMBERSHIP_PROFILE_UPDATE_NAME, self._background_add_membership_profile
        )

    def _store_room_members_txn(self, txn, events, backfilled):
        """Store a room member in the database.
        """
        self._simple_insert_many_txn(
            txn,
            table="room_memberships",
            values=[
                {
                    "event_id": event.event_id,
                    "user_id": event.state_key,
                    "sender": event.user_id,
                    "room_id": event.room_id,
                    "membership": event.membership,
                    "display_name": event.content.get("displayname", None),
                    "avatar_url": event.content.get("avatar_url", None),
                }
                for event in events
            ]
        )

        for event in events:
            txn.call_after(
                self._membership_stream_cache.entity_has_changed,
                event.state_key, event.internal_metadata.stream_ordering
            )
            txn.call_after(
                self.get_invited_rooms_for_user.invalidate, (event.state_key,)
            )

            # We update the local_invites table only if the event is "current",
            # i.e., its something that has just happened.
            # The only current event that can also be an outlier is if its an
            # invite that has come in across federation.
            is_new_state = not backfilled and (
                not event.internal_metadata.is_outlier()
                or event.internal_metadata.is_invite_from_remote()
            )
            is_mine = self.hs.is_mine_id(event.state_key)
            if is_new_state and is_mine:
                if event.membership == Membership.INVITE:
                    self._simple_insert_txn(
                        txn,
                        table="local_invites",
                        values={
                            "event_id": event.event_id,
                            "invitee": event.state_key,
                            "inviter": event.sender,
                            "room_id": event.room_id,
                            "stream_id": event.internal_metadata.stream_ordering,
                        }
                    )
                else:
                    sql = (
                        "UPDATE local_invites SET stream_id = ?, replaced_by = ? WHERE"
                        " room_id = ? AND invitee = ? AND locally_rejected is NULL"
                        " AND replaced_by is NULL"
                    )

                    txn.execute(sql, (
                        event.internal_metadata.stream_ordering,
                        event.event_id,
                        event.room_id,
                        event.state_key,
                    ))

    @defer.inlineCallbacks
    def locally_reject_invite(self, user_id, room_id):
        sql = (
            "UPDATE local_invites SET stream_id = ?, locally_rejected = ? WHERE"
            " room_id = ? AND invitee = ? AND locally_rejected is NULL"
            " AND replaced_by is NULL"
        )

        def f(txn, stream_ordering):
            txn.execute(sql, (
                stream_ordering,
                True,
                room_id,
                user_id,
            ))

        with self._stream_id_gen.get_next() as stream_ordering:
            yield self.runInteraction("locally_reject_invite", f, stream_ordering)

    @cached(max_entries=500000, iterable=True)
    def get_users_in_room(self, room_id):
        def f(txn):

            rows = self._get_members_rows_txn(
                txn,
                room_id=room_id,
                membership=Membership.JOIN,
            )

            return [r["user_id"] for r in rows]
        return self.runInteraction("get_users_in_room", f)

    @cached()
    def get_invited_rooms_for_user(self, user_id):
        """ Get all the rooms the user is invited to
        Args:
            user_id (str): The user ID.
        Returns:
            A deferred list of RoomsForUser.
        """

        return self.get_rooms_for_user_where_membership_is(
            user_id, [Membership.INVITE]
        )

    @defer.inlineCallbacks
    def get_invite_for_user_in_room(self, user_id, room_id):
        """Gets the invite for the given user and room

        Args:
            user_id (str)
            room_id (str)

        Returns:
            Deferred: Resolves to either a RoomsForUser or None if no invite was
                found.
        """
        invites = yield self.get_invited_rooms_for_user(user_id)
        for invite in invites:
            if invite.room_id == room_id:
                defer.returnValue(invite)
        defer.returnValue(None)

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

        do_invite = Membership.INVITE in membership_list
        membership_list = [m for m in membership_list if m != Membership.INVITE]

        results = []
        if membership_list:
            where_clause = "user_id = ? AND (%s) AND forgotten = 0" % (
                " OR ".join(["membership = ?" for _ in membership_list]),
            )

            args = [user_id]
            args.extend(membership_list)

            sql = (
                "SELECT m.room_id, m.sender, m.membership, m.event_id, e.stream_ordering"
                " FROM current_state_events as c"
                " INNER JOIN room_memberships as m"
                " ON m.event_id = c.event_id"
                " INNER JOIN events as e"
                " ON e.event_id = c.event_id"
                " AND m.room_id = c.room_id"
                " AND m.user_id = c.state_key"
                " WHERE c.type = 'm.room.member' AND %s"
            ) % (where_clause,)

            txn.execute(sql, args)
            results = [
                RoomsForUser(**r) for r in self.cursor_to_dict(txn)
            ]

        if do_invite:
            sql = (
                "SELECT i.room_id, inviter, i.event_id, e.stream_ordering"
                " FROM local_invites as i"
                " INNER JOIN events as e USING (event_id)"
                " WHERE invitee = ? AND locally_rejected is NULL"
                " AND replaced_by is NULL"
            )

            txn.execute(sql, (user_id,))
            results.extend(RoomsForUser(
                room_id=r["room_id"],
                sender=r["inviter"],
                event_id=r["event_id"],
                stream_ordering=r["stream_ordering"],
                membership=Membership.INVITE,
            ) for r in self.cursor_to_dict(txn))

        return results

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
            " WHERE c.type = 'm.room.member' AND %(where)s"
        ) % {
            "where": where_clause,
        }

        txn.execute(sql, where_values)
        rows = self.cursor_to_dict(txn)

        return rows

    @cached(max_entries=500000, iterable=True)
    def get_rooms_for_user(self, user_id):
        return self.get_rooms_for_user_where_membership_is(
            user_id, membership_list=[Membership.JOIN],
        )

    @cachedInlineCallbacks(max_entries=500000, cache_context=True, iterable=True)
    def get_users_who_share_room_with_user(self, user_id, cache_context):
        """Returns the set of users who share a room with `user_id`
        """
        rooms = yield self.get_rooms_for_user(
            user_id, on_invalidate=cache_context.invalidate,
        )

        user_who_share_room = set()
        for room in rooms:
            user_ids = yield self.get_users_in_room(
                room.room_id, on_invalidate=cache_context.invalidate,
            )
            user_who_share_room.update(user_ids)

        defer.returnValue(user_who_share_room)

    def forget(self, user_id, room_id):
        """Indicate that user_id wishes to discard history for room_id."""
        def f(txn):
            sql = (
                "UPDATE"
                "  room_memberships"
                " SET"
                "  forgotten = 1"
                " WHERE"
                "  user_id = ?"
                " AND"
                "  room_id = ?"
            )
            txn.execute(sql, (user_id, room_id))

            txn.call_after(self.was_forgotten_at.invalidate_all)
            txn.call_after(self.did_forget.invalidate, (user_id, room_id))
            self._invalidate_cache_and_stream(
                txn, self.who_forgot_in_room, (room_id,)
            )
        return self.runInteraction("forget_membership", f)

    @cachedInlineCallbacks(num_args=2)
    def did_forget(self, user_id, room_id):
        """Returns whether user_id has elected to discard history for room_id.

        Returns False if they have since re-joined."""
        def f(txn):
            sql = (
                "SELECT"
                "  COUNT(*)"
                " FROM"
                "  room_memberships"
                " WHERE"
                "  user_id = ?"
                " AND"
                "  room_id = ?"
                " AND"
                "  forgotten = 0"
            )
            txn.execute(sql, (user_id, room_id))
            rows = txn.fetchall()
            return rows[0][0]
        count = yield self.runInteraction("did_forget_membership", f)
        defer.returnValue(count == 0)

    @cachedInlineCallbacks(num_args=3)
    def was_forgotten_at(self, user_id, room_id, event_id):
        """Returns whether user_id has elected to discard history for room_id at
        event_id.

        event_id must be a membership event."""
        def f(txn):
            sql = (
                "SELECT"
                "  forgotten"
                " FROM"
                "  room_memberships"
                " WHERE"
                "  user_id = ?"
                " AND"
                "  room_id = ?"
                " AND"
                "  event_id = ?"
            )
            txn.execute(sql, (user_id, room_id, event_id))
            rows = txn.fetchall()
            return rows[0][0]
        forgot = yield self.runInteraction("did_forget_membership_at", f)
        defer.returnValue(forgot == 1)

    @cached()
    def who_forgot_in_room(self, room_id):
        return self._simple_select_list(
            table="room_memberships",
            retcols=("user_id", "event_id"),
            keyvalues={
                "room_id": room_id,
                "forgotten": 1,
            },
            desc="who_forgot"
        )

    def get_joined_users_from_context(self, event, context):
        state_group = context.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        return self._get_joined_users_from_context(
            event.room_id, state_group, context.current_state_ids, event=event,
        )

    def get_joined_users_from_state(self, room_id, state_group, state_ids):
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        return self._get_joined_users_from_context(
            room_id, state_group, state_ids,
        )

    @cachedInlineCallbacks(num_args=2, cache_context=True, iterable=True,
                           max_entries=100000)
    def _get_joined_users_from_context(self, room_id, state_group, current_state_ids,
                                       cache_context, event=None):
        # We don't use `state_group`, it's there so that we can cache based
        # on it. However, it's important that it's never None, since two current_states
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        member_event_ids = [
            e_id
            for key, e_id in current_state_ids.iteritems()
            if key[0] == EventTypes.Member
        ]

        rows = yield self._simple_select_many_batch(
            table="room_memberships",
            column="event_id",
            iterable=member_event_ids,
            retcols=['user_id', 'display_name', 'avatar_url'],
            keyvalues={
                "membership": Membership.JOIN,
            },
            batch_size=500,
            desc="_get_joined_users_from_context",
        )

        users_in_room = {
            row["user_id"]: {
                "display_name": row["display_name"],
                "avatar_url": row["avatar_url"],
            }
            for row in rows
        }

        if event is not None and event.type == EventTypes.Member:
            if event.membership == Membership.JOIN:
                if event.event_id in member_event_ids:
                    users_in_room[event.state_key] = {
                        "display_name": event.content.get("displayname", None),
                        "avatar_url": event.content.get("avatar_url", None),
                    }

        defer.returnValue(users_in_room)

    def is_host_joined(self, room_id, host, state_group, state_ids):
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        return self._is_host_joined(
            room_id, host, state_group, state_ids
        )

    @cachedInlineCallbacks(num_args=3)
    def _is_host_joined(self, room_id, host, state_group, current_state_ids):
        # We don't use `state_group`, its there so that we can cache based
        # on it. However, its important that its never None, since two current_state's
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        for (etype, state_key), event_id in current_state_ids.items():
            if etype == EventTypes.Member:
                try:
                    if get_domain_from_id(state_key) != host:
                        continue
                except:
                    logger.warn("state_key not user_id: %s", state_key)
                    continue

                event = yield self.get_event(event_id, allow_none=True)
                if event and event.content["membership"] == Membership.JOIN:
                    defer.returnValue(True)

        defer.returnValue(False)

    @defer.inlineCallbacks
    def _background_add_membership_profile(self, progress, batch_size):
        target_min_stream_id = progress.get(
            "target_min_stream_id_inclusive", self._min_stream_order_on_start
        )
        max_stream_id = progress.get(
            "max_stream_id_exclusive", self._stream_order_on_start + 1
        )

        INSERT_CLUMP_SIZE = 1000

        def add_membership_profile_txn(txn):
            sql = ("""
                SELECT stream_ordering, event_id, events.room_id, content
                FROM events
                INNER JOIN room_memberships USING (event_id)
                WHERE ? <= stream_ordering AND stream_ordering < ?
                AND type = 'm.room.member'
                ORDER BY stream_ordering DESC
                LIMIT ?
            """)

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = self.cursor_to_dict(txn)
            if not rows:
                return 0

            min_stream_id = rows[-1]["stream_ordering"]

            to_update = []
            for row in rows:
                event_id = row["event_id"]
                room_id = row["room_id"]
                try:
                    content = json.loads(row["content"])
                except:
                    continue

                display_name = content.get("displayname", None)
                avatar_url = content.get("avatar_url", None)

                if display_name or avatar_url:
                    to_update.append((
                        display_name, avatar_url, event_id, room_id
                    ))

            to_update_sql = ("""
                UPDATE room_memberships SET display_name = ?, avatar_url = ?
                WHERE event_id = ? AND room_id = ?
            """)
            for index in range(0, len(to_update), INSERT_CLUMP_SIZE):
                clump = to_update[index:index + INSERT_CLUMP_SIZE]
                txn.executemany(to_update_sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
            }

            self._background_update_progress_txn(
                txn, _MEMBERSHIP_PROFILE_UPDATE_NAME, progress
            )

            return len(rows)

        result = yield self.runInteraction(
            _MEMBERSHIP_PROFILE_UPDATE_NAME, add_membership_profile_txn
        )

        if not result:
            yield self._end_background_update(_MEMBERSHIP_PROFILE_UPDATE_NAME)

        defer.returnValue(result)

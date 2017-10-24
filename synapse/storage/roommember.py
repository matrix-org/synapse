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
from synapse.util.async import Linearizer
from synapse.util.caches import intern_string
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks
from synapse.util.stringutils import to_ascii

from synapse.api.constants import Membership, EventTypes
from synapse.types import get_domain_from_id

import logging
import ujson as json

logger = logging.getLogger(__name__)


RoomsForUser = namedtuple(
    "RoomsForUser",
    ("room_id", "sender", "membership", "event_id", "stream_ordering")
)


# We store this using a namedtuple so that we save about 3x space over using a
# dict.
ProfileInfo = namedtuple(
    "ProfileInfo", ("avatar_url", "display_name")
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

    @cachedInlineCallbacks(max_entries=100000, iterable=True, cache_context=True)
    def get_hosts_in_room(self, room_id, cache_context):
        """Returns the set of all hosts currently in the room
        """
        user_ids = yield self.get_users_in_room(
            room_id, on_invalidate=cache_context.invalidate,
        )
        hosts = frozenset(get_domain_from_id(user_id) for user_id in user_ids)
        defer.returnValue(hosts)

    @cached(max_entries=100000, iterable=True)
    def get_users_in_room(self, room_id):
        def f(txn):
            sql = (
                "SELECT m.user_id FROM room_memberships as m"
                " INNER JOIN current_state_events as c"
                " ON m.event_id = c.event_id "
                " AND m.room_id = c.room_id "
                " AND m.user_id = c.state_key"
                " WHERE c.type = 'm.room.member' AND c.room_id = ? AND m.membership = ?"
            )

            txn.execute(sql, (room_id, Membership.JOIN,))
            return [to_ascii(r[0]) for r in txn]
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

    @cachedInlineCallbacks(max_entries=500000, iterable=True)
    def get_rooms_for_user(self, user_id):
        """Returns a set of room_ids the user is currently joined to
        """
        rooms = yield self.get_rooms_for_user_where_membership_is(
            user_id, membership_list=[Membership.JOIN],
        )
        defer.returnValue(frozenset(r.room_id for r in rooms))

    @cachedInlineCallbacks(max_entries=500000, cache_context=True, iterable=True)
    def get_users_who_share_room_with_user(self, user_id, cache_context):
        """Returns the set of users who share a room with `user_id`
        """
        room_ids = yield self.get_rooms_for_user(
            user_id, on_invalidate=cache_context.invalidate,
        )

        user_who_share_room = set()
        for room_id in room_ids:
            user_ids = yield self.get_users_in_room(
                room_id, on_invalidate=cache_context.invalidate,
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
            event.room_id, state_group, context.current_state_ids,
            event=event,
            context=context,
        )

    def get_joined_users_from_state(self, room_id, state_entry):
        state_group = state_entry.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        return self._get_joined_users_from_context(
            room_id, state_group, state_entry.state, context=state_entry,
        )

    @cachedInlineCallbacks(num_args=2, cache_context=True, iterable=True,
                           max_entries=100000)
    def _get_joined_users_from_context(self, room_id, state_group, current_state_ids,
                                       cache_context, event=None, context=None):
        # We don't use `state_group`, it's there so that we can cache based
        # on it. However, it's important that it's never None, since two current_states
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        users_in_room = {}
        member_event_ids = [
            e_id
            for key, e_id in current_state_ids.iteritems()
            if key[0] == EventTypes.Member
        ]

        if context is not None:
            # If we have a context with a delta from a previous state group,
            # check if we also have the result from the previous group in cache.
            # If we do then we can reuse that result and simply update it with
            # any membership changes in `delta_ids`
            if context.prev_group and context.delta_ids:
                prev_res = self._get_joined_users_from_context.cache.get(
                    (room_id, context.prev_group), None
                )
                if prev_res and isinstance(prev_res, dict):
                    users_in_room = dict(prev_res)
                    member_event_ids = [
                        e_id
                        for key, e_id in context.delta_ids.iteritems()
                        if key[0] == EventTypes.Member
                    ]
                    for etype, state_key in context.delta_ids:
                        users_in_room.pop(state_key, None)

        # We check if we have any of the member event ids in the event cache
        # before we ask the DB

        # We don't update the event cache hit ratio as it completely throws off
        # the hit ratio counts. After all, we don't populate the cache if we
        # miss it here
        event_map = self._get_events_from_cache(
            member_event_ids,
            allow_rejected=False,
            update_metrics=False,
        )

        missing_member_event_ids = []
        for event_id in member_event_ids:
            ev_entry = event_map.get(event_id)
            if ev_entry:
                if ev_entry.event.membership == Membership.JOIN:
                    users_in_room[to_ascii(ev_entry.event.state_key)] = ProfileInfo(
                        display_name=to_ascii(
                            ev_entry.event.content.get("displayname", None)
                        ),
                        avatar_url=to_ascii(
                            ev_entry.event.content.get("avatar_url", None)
                        ),
                    )
            else:
                missing_member_event_ids.append(event_id)

        if missing_member_event_ids:
            rows = yield self._simple_select_many_batch(
                table="room_memberships",
                column="event_id",
                iterable=missing_member_event_ids,
                retcols=('user_id', 'display_name', 'avatar_url',),
                keyvalues={
                    "membership": Membership.JOIN,
                },
                batch_size=500,
                desc="_get_joined_users_from_context",
            )

            users_in_room.update({
                to_ascii(row["user_id"]): ProfileInfo(
                    avatar_url=to_ascii(row["avatar_url"]),
                    display_name=to_ascii(row["display_name"]),
                )
                for row in rows
            })

        if event is not None and event.type == EventTypes.Member:
            if event.membership == Membership.JOIN:
                if event.event_id in member_event_ids:
                    users_in_room[to_ascii(event.state_key)] = ProfileInfo(
                        display_name=to_ascii(event.content.get("displayname", None)),
                        avatar_url=to_ascii(event.content.get("avatar_url", None)),
                    )

        defer.returnValue(users_in_room)

    @cachedInlineCallbacks(max_entries=10000)
    def is_host_joined(self, room_id, host):
        if '%' in host or '_' in host:
            raise Exception("Invalid host name")

        sql = """
            SELECT state_key FROM current_state_events AS c
            INNER JOIN room_memberships USING (event_id)
            WHERE membership = 'join'
                AND type = 'm.room.member'
                AND c.room_id = ?
                AND state_key LIKE ?
            LIMIT 1
        """

        # We do need to be careful to ensure that host doesn't have any wild cards
        # in it, but we checked above for known ones and we'll check below that
        # the returned user actually has the correct domain.
        like_clause = "%:" + host

        rows = yield self._execute("is_host_joined", None, sql, room_id, like_clause)

        if not rows:
            defer.returnValue(False)

        user_id = rows[0][0]
        if get_domain_from_id(user_id) != host:
            # This can only happen if the host name has something funky in it
            raise Exception("Invalid host name")

        defer.returnValue(True)

    @cachedInlineCallbacks()
    def was_host_joined(self, room_id, host):
        """Check whether the server is or ever was in the room.

        Args:
            room_id (str)
            host (str)

        Returns:
            Deferred: Resolves to True if the host is/was in the room, otherwise
            False.
        """
        if '%' in host or '_' in host:
            raise Exception("Invalid host name")

        sql = """
            SELECT user_id FROM room_memberships
            WHERE room_id = ?
                AND user_id LIKE ?
                AND membership = 'join'
            LIMIT 1
        """

        # We do need to be careful to ensure that host doesn't have any wild cards
        # in it, but we checked above for known ones and we'll check below that
        # the returned user actually has the correct domain.
        like_clause = "%:" + host

        rows = yield self._execute("was_host_joined", None, sql, room_id, like_clause)

        if not rows:
            defer.returnValue(False)

        user_id = rows[0][0]
        if get_domain_from_id(user_id) != host:
            # This can only happen if the host name has something funky in it
            raise Exception("Invalid host name")

        defer.returnValue(True)

    def get_joined_hosts(self, room_id, state_entry):
        state_group = state_entry.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        return self._get_joined_hosts(
            room_id, state_group, state_entry.state, state_entry=state_entry,
        )

    @cachedInlineCallbacks(num_args=2, max_entries=10000, iterable=True)
    # @defer.inlineCallbacks
    def _get_joined_hosts(self, room_id, state_group, current_state_ids, state_entry):
        # We don't use `state_group`, its there so that we can cache based
        # on it. However, its important that its never None, since two current_state's
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        cache = self._get_joined_hosts_cache(room_id)
        joined_hosts = yield cache.get_destinations(state_entry)

        defer.returnValue(joined_hosts)

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
                except Exception:
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

    @cached(max_entries=10000, iterable=True)
    def _get_joined_hosts_cache(self, room_id):
        return _JoinedHostsCache(self, room_id)


class _JoinedHostsCache(object):
    """Cache for joined hosts in a room that is optimised to handle updates
    via state deltas.
    """

    def __init__(self, store, room_id):
        self.store = store
        self.room_id = room_id

        self.hosts_to_joined_users = {}

        self.state_group = object()

        self.linearizer = Linearizer("_JoinedHostsCache")

        self._len = 0

    @defer.inlineCallbacks
    def get_destinations(self, state_entry):
        """Get set of destinations for a state entry

        Args:
            state_entry(synapse.state._StateCacheEntry)
        """
        if state_entry.state_group == self.state_group:
            defer.returnValue(frozenset(self.hosts_to_joined_users))

        with (yield self.linearizer.queue(())):
            if state_entry.state_group == self.state_group:
                pass
            elif state_entry.prev_group == self.state_group:
                for (typ, state_key), event_id in state_entry.delta_ids.iteritems():
                    if typ != EventTypes.Member:
                        continue

                    host = intern_string(get_domain_from_id(state_key))
                    user_id = state_key
                    known_joins = self.hosts_to_joined_users.setdefault(host, set())

                    event = yield self.store.get_event(event_id)
                    if event.membership == Membership.JOIN:
                        known_joins.add(user_id)
                    else:
                        known_joins.discard(user_id)

                        if not known_joins:
                            self.hosts_to_joined_users.pop(host, None)
            else:
                joined_users = yield self.store.get_joined_users_from_state(
                    self.room_id, state_entry,
                )

                self.hosts_to_joined_users = {}
                for user_id in joined_users:
                    host = intern_string(get_domain_from_id(user_id))
                    self.hosts_to_joined_users.setdefault(host, set()).add(user_id)

            if state_entry.state_group:
                self.state_group = state_entry.state_group
            else:
                self.state_group = object()
            self._len = sum(len(v) for v in self.hosts_to_joined_users.itervalues())
        defer.returnValue(frozenset(self.hosts_to_joined_users))

    def __len__(self):
        return self._len

# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from typing import Iterable, List, Set

from six import iteritems, itervalues

from canonicaljson import json

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage._base import (
    LoggingTransaction,
    SQLBaseStore,
    make_in_list_sql_clause,
)
from synapse.storage.data_stores.main.events_worker import EventsWorkerStore
from synapse.storage.database import Database
from synapse.storage.engines import Sqlite3Engine
from synapse.storage.roommember import (
    GetRoomsForUserWithStreamOrdering,
    MemberSummary,
    ProfileInfo,
    RoomsForUser,
)
from synapse.types import Collection, get_domain_from_id
from synapse.util.async_helpers import Linearizer
from synapse.util.caches import intern_string
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks, cachedList
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


_MEMBERSHIP_PROFILE_UPDATE_NAME = "room_membership_profile_update"
_CURRENT_STATE_MEMBERSHIP_UPDATE_NAME = "current_state_events_membership"


class RoomMemberWorkerStore(EventsWorkerStore):
    def __init__(self, database: Database, db_conn, hs):
        super(RoomMemberWorkerStore, self).__init__(database, db_conn, hs)

        # Is the current_state_events.membership up to date? Or is the
        # background update still running?
        self._current_state_events_membership_up_to_date = False

        txn = LoggingTransaction(
            db_conn.cursor(),
            name="_check_safe_current_state_events_membership_updated",
            database_engine=self.database_engine,
        )
        self._check_safe_current_state_events_membership_updated_txn(txn)
        txn.close()

        if self.hs.config.metrics_flags.known_servers:
            self._known_servers_count = 1
            self.hs.get_clock().looping_call(
                run_as_background_process,
                60 * 1000,
                "_count_known_servers",
                self._count_known_servers,
            )
            self.hs.get_clock().call_later(
                1000,
                run_as_background_process,
                "_count_known_servers",
                self._count_known_servers,
            )
            LaterGauge(
                "synapse_federation_known_servers",
                "",
                [],
                lambda: self._known_servers_count,
            )

    @defer.inlineCallbacks
    def _count_known_servers(self):
        """
        Count the servers that this server knows about.

        The statistic is stored on the class for the
        `synapse_federation_known_servers` LaterGauge to collect.
        """

        def _transact(txn):
            if isinstance(self.database_engine, Sqlite3Engine):
                query = """
                    SELECT COUNT(DISTINCT substr(out.user_id, pos+1))
                    FROM (
                        SELECT rm.user_id as user_id, instr(rm.user_id, ':')
                            AS pos FROM room_memberships as rm
                        INNER JOIN current_state_events as c ON rm.event_id = c.event_id
                        WHERE c.type = 'm.room.member'
                    ) as out
                """
            else:
                query = """
                    SELECT COUNT(DISTINCT split_part(state_key, ':', 2))
                    FROM current_state_events
                    WHERE type = 'm.room.member' AND membership = 'join';
                """
            txn.execute(query)
            return list(txn)[0][0]

        count = yield self.db.runInteraction("get_known_servers", _transact)

        # We always know about ourselves, even if we have nothing in
        # room_memberships (for example, the server is new).
        self._known_servers_count = max([count, 1])
        return self._known_servers_count

    def _check_safe_current_state_events_membership_updated_txn(self, txn):
        """Checks if it is safe to assume the new current_state_events
        membership column is up to date
        """

        pending_update = self.db.simple_select_one_txn(
            txn,
            table="background_updates",
            keyvalues={"update_name": _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME},
            retcols=["update_name"],
            allow_none=True,
        )

        self._current_state_events_membership_up_to_date = not pending_update

        # If the update is still running, reschedule to run.
        if pending_update:
            self._clock.call_later(
                15.0,
                run_as_background_process,
                "_check_safe_current_state_events_membership_updated",
                self.db.runInteraction,
                "_check_safe_current_state_events_membership_updated",
                self._check_safe_current_state_events_membership_updated_txn,
            )

    @cached(max_entries=100000, iterable=True)
    def get_users_in_room(self, room_id):
        return self.db.runInteraction(
            "get_users_in_room", self.get_users_in_room_txn, room_id
        )

    def get_users_in_room_txn(self, txn, room_id):
        # If we can assume current_state_events.membership is up to date
        # then we can avoid a join, which is a Very Good Thing given how
        # frequently this function gets called.
        if self._current_state_events_membership_up_to_date:
            sql = """
                SELECT state_key FROM current_state_events
                WHERE type = 'm.room.member' AND room_id = ? AND membership = ?
            """
        else:
            sql = """
                SELECT state_key FROM room_memberships as m
                INNER JOIN current_state_events as c
                ON m.event_id = c.event_id
                AND m.room_id = c.room_id
                AND m.user_id = c.state_key
                WHERE c.type = 'm.room.member' AND c.room_id = ? AND m.membership = ?
            """

        txn.execute(sql, (room_id, Membership.JOIN))
        return [r[0] for r in txn]

    @cached(max_entries=100000)
    def get_room_summary(self, room_id):
        """ Get the details of a room roughly suitable for use by the room
        summary extension to /sync. Useful when lazy loading room members.
        Args:
            room_id (str): The room ID to query
        Returns:
            Deferred[dict[str, MemberSummary]:
                dict of membership states, pointing to a MemberSummary named tuple.
        """

        def _get_room_summary_txn(txn):
            # first get counts.
            # We do this all in one transaction to keep the cache small.
            # FIXME: get rid of this when we have room_stats

            # If we can assume current_state_events.membership is up to date
            # then we can avoid a join, which is a Very Good Thing given how
            # frequently this function gets called.
            if self._current_state_events_membership_up_to_date:
                # Note, rejected events will have a null membership field, so
                # we we manually filter them out.
                sql = """
                    SELECT count(*), membership FROM current_state_events
                    WHERE type = 'm.room.member' AND room_id = ?
                        AND membership IS NOT NULL
                    GROUP BY membership
                """
            else:
                sql = """
                    SELECT count(*), m.membership FROM room_memberships as m
                    INNER JOIN current_state_events as c
                    ON m.event_id = c.event_id
                    AND m.room_id = c.room_id
                    AND m.user_id = c.state_key
                    WHERE c.type = 'm.room.member' AND c.room_id = ?
                    GROUP BY m.membership
                """

            txn.execute(sql, (room_id,))
            res = {}
            for count, membership in txn:
                summary = res.setdefault(membership, MemberSummary([], count))

            # we order by membership and then fairly arbitrarily by event_id so
            # heroes are consistent
            if self._current_state_events_membership_up_to_date:
                # Note, rejected events will have a null membership field, so
                # we we manually filter them out.
                sql = """
                    SELECT state_key, membership, event_id
                    FROM current_state_events
                    WHERE type = 'm.room.member' AND room_id = ?
                        AND membership IS NOT NULL
                    ORDER BY
                        CASE membership WHEN ? THEN 1 WHEN ? THEN 2 ELSE 3 END ASC,
                        event_id ASC
                    LIMIT ?
                """
            else:
                sql = """
                    SELECT c.state_key, m.membership, c.event_id
                    FROM room_memberships as m
                    INNER JOIN current_state_events as c USING (room_id, event_id)
                    WHERE c.type = 'm.room.member' AND c.room_id = ?
                    ORDER BY
                        CASE m.membership WHEN ? THEN 1 WHEN ? THEN 2 ELSE 3 END ASC,
                        c.event_id ASC
                    LIMIT ?
                """

            # 6 is 5 (number of heroes) plus 1, in case one of them is the calling user.
            txn.execute(sql, (room_id, Membership.JOIN, Membership.INVITE, 6))
            for user_id, membership, event_id in txn:
                summary = res[membership]
                # we will always have a summary for this membership type at this
                # point given the summary currently contains the counts.
                members = summary.members
                members.append((user_id, event_id))

            return res

        return self.db.runInteraction("get_room_summary", _get_room_summary_txn)

    def _get_user_counts_in_room_txn(self, txn, room_id):
        """
        Get the user count in a room by membership.

        Args:
            room_id (str)
            membership (Membership)

        Returns:
            Deferred[int]
        """
        sql = """
        SELECT m.membership, count(*) FROM room_memberships as m
            INNER JOIN current_state_events as c USING(event_id)
            WHERE c.type = 'm.room.member' AND c.room_id = ?
            GROUP BY m.membership
        """

        txn.execute(sql, (room_id,))
        return {row[0]: row[1] for row in txn}

    @cached()
    def get_invited_rooms_for_local_user(self, user_id):
        """ Get all the rooms the *local* user is invited to

        Args:
            user_id (str): The user ID.
        Returns:
            A deferred list of RoomsForUser.
        """

        return self.get_rooms_for_local_user_where_membership_is(
            user_id, [Membership.INVITE]
        )

    @defer.inlineCallbacks
    def get_invite_for_local_user_in_room(self, user_id, room_id):
        """Gets the invite for the given *local* user and room

        Args:
            user_id (str)
            room_id (str)

        Returns:
            Deferred: Resolves to either a RoomsForUser or None if no invite was
                found.
        """
        invites = yield self.get_invited_rooms_for_local_user(user_id)
        for invite in invites:
            if invite.room_id == room_id:
                return invite
        return None

    @defer.inlineCallbacks
    def get_rooms_for_local_user_where_membership_is(self, user_id, membership_list):
        """ Get all the rooms for this *local* user where the membership for this user
        matches one in the membership list.

        Filters out forgotten rooms.

        Args:
            user_id (str): The user ID.
            membership_list (list): A list of synapse.api.constants.Membership
            values which the user must be in.

        Returns:
            Deferred[list[RoomsForUser]]
        """
        if not membership_list:
            return defer.succeed(None)

        rooms = yield self.db.runInteraction(
            "get_rooms_for_local_user_where_membership_is",
            self._get_rooms_for_local_user_where_membership_is_txn,
            user_id,
            membership_list,
        )

        # Now we filter out forgotten rooms
        forgotten_rooms = yield self.get_forgotten_rooms_for_user(user_id)
        return [room for room in rooms if room.room_id not in forgotten_rooms]

    def _get_rooms_for_local_user_where_membership_is_txn(
        self, txn, user_id, membership_list
    ):
        # Paranoia check.
        if not self.hs.is_mine_id(user_id):
            raise Exception(
                "Cannot call 'get_rooms_for_local_user_where_membership_is' on non-local user %r"
                % (user_id,),
            )

        clause, args = make_in_list_sql_clause(
            self.database_engine, "c.membership", membership_list
        )

        sql = """
            SELECT room_id, e.sender, c.membership, event_id, e.stream_ordering
            FROM local_current_membership AS c
            INNER JOIN events AS e USING (room_id, event_id)
            WHERE
                user_id = ?
                AND %s
        """ % (
            clause,
        )

        txn.execute(sql, (user_id, *args))
        results = [RoomsForUser(**r) for r in self.db.cursor_to_dict(txn)]

        return results

    @cached(max_entries=500000, iterable=True)
    def get_rooms_for_user_with_stream_ordering(self, user_id):
        """Returns a set of room_ids the user is currently joined to.

        If a remote user only returns rooms this server is currently
        participating in.

        Args:
            user_id (str)

        Returns:
            Deferred[frozenset[GetRoomsForUserWithStreamOrdering]]: Returns
            the rooms the user is in currently, along with the stream ordering
            of the most recent join for that user and room.
        """
        return self.db.runInteraction(
            "get_rooms_for_user_with_stream_ordering",
            self._get_rooms_for_user_with_stream_ordering_txn,
            user_id,
        )

    def _get_rooms_for_user_with_stream_ordering_txn(self, txn, user_id):
        # We use `current_state_events` here and not `local_current_membership`
        # as a) this gets called with remote users and b) this only gets called
        # for rooms the server is participating in.
        if self._current_state_events_membership_up_to_date:
            sql = """
                SELECT room_id, e.stream_ordering
                FROM current_state_events AS c
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    c.type = 'm.room.member'
                    AND state_key = ?
                    AND c.membership = ?
            """
        else:
            sql = """
                SELECT room_id, e.stream_ordering
                FROM current_state_events AS c
                INNER JOIN room_memberships AS m USING (room_id, event_id)
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    c.type = 'm.room.member'
                    AND state_key = ?
                    AND m.membership = ?
            """

        txn.execute(sql, (user_id, Membership.JOIN))
        results = frozenset(GetRoomsForUserWithStreamOrdering(*row) for row in txn)

        return results

    async def get_users_server_still_shares_room_with(
        self, user_ids: Collection[str]
    ) -> Set[str]:
        """Given a list of users return the set that the server still share a
        room with.
        """

        if not user_ids:
            return set()

        def _get_users_server_still_shares_room_with_txn(txn):
            sql = """
                SELECT state_key FROM current_state_events
                WHERE
                    type = 'm.room.member'
                    AND membership = 'join'
                    AND %s
                GROUP BY state_key
            """

            clause, args = make_in_list_sql_clause(
                self.database_engine, "state_key", user_ids
            )

            txn.execute(sql % (clause,), args)

            return {row[0] for row in txn}

        return await self.db.runInteraction(
            "get_users_server_still_shares_room_with",
            _get_users_server_still_shares_room_with_txn,
        )

    @defer.inlineCallbacks
    def get_rooms_for_user(self, user_id, on_invalidate=None):
        """Returns a set of room_ids the user is currently joined to.

        If a remote user only returns rooms this server is currently
        participating in.
        """
        rooms = yield self.get_rooms_for_user_with_stream_ordering(
            user_id, on_invalidate=on_invalidate
        )
        return frozenset(r.room_id for r in rooms)

    @cachedInlineCallbacks(max_entries=500000, cache_context=True, iterable=True)
    def get_users_who_share_room_with_user(self, user_id, cache_context):
        """Returns the set of users who share a room with `user_id`
        """
        room_ids = yield self.get_rooms_for_user(
            user_id, on_invalidate=cache_context.invalidate
        )

        user_who_share_room = set()
        for room_id in room_ids:
            user_ids = yield self.get_users_in_room(
                room_id, on_invalidate=cache_context.invalidate
            )
            user_who_share_room.update(user_ids)

        return user_who_share_room

    @defer.inlineCallbacks
    def get_joined_users_from_context(self, event, context):
        state_group = context.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        current_state_ids = yield context.get_current_state_ids()
        result = yield self._get_joined_users_from_context(
            event.room_id, state_group, current_state_ids, event=event, context=context
        )
        return result

    @defer.inlineCallbacks
    def get_joined_users_from_state(self, room_id, state_entry):
        state_group = state_entry.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        with Measure(self._clock, "get_joined_users_from_state"):
            return (
                yield self._get_joined_users_from_context(
                    room_id, state_group, state_entry.state, context=state_entry
                )
            )

    @cachedInlineCallbacks(
        num_args=2, cache_context=True, iterable=True, max_entries=100000
    )
    def _get_joined_users_from_context(
        self,
        room_id,
        state_group,
        current_state_ids,
        cache_context,
        event=None,
        context=None,
    ):
        # We don't use `state_group`, it's there so that we can cache based
        # on it. However, it's important that it's never None, since two current_states
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        users_in_room = {}
        member_event_ids = [
            e_id
            for key, e_id in iteritems(current_state_ids)
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
                        for key, e_id in iteritems(context.delta_ids)
                        if key[0] == EventTypes.Member
                    ]
                    for etype, state_key in context.delta_ids:
                        if etype == EventTypes.Member:
                            users_in_room.pop(state_key, None)

        # We check if we have any of the member event ids in the event cache
        # before we ask the DB

        # We don't update the event cache hit ratio as it completely throws off
        # the hit ratio counts. After all, we don't populate the cache if we
        # miss it here
        event_map = self._get_events_from_cache(
            member_event_ids, allow_rejected=False, update_metrics=False
        )

        missing_member_event_ids = []
        for event_id in member_event_ids:
            ev_entry = event_map.get(event_id)
            if ev_entry:
                if ev_entry.event.membership == Membership.JOIN:
                    users_in_room[ev_entry.event.state_key] = ProfileInfo(
                        display_name=ev_entry.event.content.get("displayname", None),
                        avatar_url=ev_entry.event.content.get("avatar_url", None),
                    )
            else:
                missing_member_event_ids.append(event_id)

        if missing_member_event_ids:
            event_to_memberships = yield self._get_joined_profiles_from_event_ids(
                missing_member_event_ids
            )
            users_in_room.update((row for row in event_to_memberships.values() if row))

        if event is not None and event.type == EventTypes.Member:
            if event.membership == Membership.JOIN:
                if event.event_id in member_event_ids:
                    users_in_room[event.state_key] = ProfileInfo(
                        display_name=event.content.get("displayname", None),
                        avatar_url=event.content.get("avatar_url", None),
                    )

        return users_in_room

    @cached(max_entries=10000)
    def _get_joined_profile_from_event_id(self, event_id):
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_joined_profile_from_event_id",
        list_name="event_ids",
        inlineCallbacks=True,
    )
    def _get_joined_profiles_from_event_ids(self, event_ids):
        """For given set of member event_ids check if they point to a join
        event and if so return the associated user and profile info.

        Args:
            event_ids (Iterable[str]): The member event IDs to lookup

        Returns:
            Deferred[dict[str, Tuple[str, ProfileInfo]|None]]: Map from event ID
            to `user_id` and ProfileInfo (or None if not join event).
        """

        rows = yield self.db.simple_select_many_batch(
            table="room_memberships",
            column="event_id",
            iterable=event_ids,
            retcols=("user_id", "display_name", "avatar_url", "event_id"),
            keyvalues={"membership": Membership.JOIN},
            batch_size=500,
            desc="_get_membership_from_event_ids",
        )

        return {
            row["event_id"]: (
                row["user_id"],
                ProfileInfo(
                    avatar_url=row["avatar_url"], display_name=row["display_name"]
                ),
            )
            for row in rows
        }

    @cachedInlineCallbacks(max_entries=10000)
    def is_host_joined(self, room_id, host):
        if "%" in host or "_" in host:
            raise Exception("Invalid host name")

        sql = """
            SELECT state_key FROM current_state_events AS c
            INNER JOIN room_memberships AS m USING (event_id)
            WHERE m.membership = 'join'
                AND type = 'm.room.member'
                AND c.room_id = ?
                AND state_key LIKE ?
            LIMIT 1
        """

        # We do need to be careful to ensure that host doesn't have any wild cards
        # in it, but we checked above for known ones and we'll check below that
        # the returned user actually has the correct domain.
        like_clause = "%:" + host

        rows = yield self.db.execute("is_host_joined", None, sql, room_id, like_clause)

        if not rows:
            return False

        user_id = rows[0][0]
        if get_domain_from_id(user_id) != host:
            # This can only happen if the host name has something funky in it
            raise Exception("Invalid host name")

        return True

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
        if "%" in host or "_" in host:
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

        rows = yield self.db.execute("was_host_joined", None, sql, room_id, like_clause)

        if not rows:
            return False

        user_id = rows[0][0]
        if get_domain_from_id(user_id) != host:
            # This can only happen if the host name has something funky in it
            raise Exception("Invalid host name")

        return True

    @defer.inlineCallbacks
    def get_joined_hosts(self, room_id, state_entry):
        state_group = state_entry.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        with Measure(self._clock, "get_joined_hosts"):
            return (
                yield self._get_joined_hosts(
                    room_id, state_group, state_entry.state, state_entry=state_entry
                )
            )

    @cachedInlineCallbacks(num_args=2, max_entries=10000, iterable=True)
    # @defer.inlineCallbacks
    def _get_joined_hosts(self, room_id, state_group, current_state_ids, state_entry):
        # We don't use `state_group`, its there so that we can cache based
        # on it. However, its important that its never None, since two current_state's
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        cache = yield self._get_joined_hosts_cache(room_id)
        joined_hosts = yield cache.get_destinations(state_entry)

        return joined_hosts

    @cached(max_entries=10000)
    def _get_joined_hosts_cache(self, room_id):
        return _JoinedHostsCache(self, room_id)

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

        count = yield self.db.runInteraction("did_forget_membership", f)
        return count == 0

    @cached()
    def get_forgotten_rooms_for_user(self, user_id):
        """Gets all rooms the user has forgotten.

        Args:
            user_id (str)

        Returns:
            Deferred[set[str]]
        """

        def _get_forgotten_rooms_for_user_txn(txn):
            # This is a slightly convoluted query that first looks up all rooms
            # that the user has forgotten in the past, then rechecks that list
            # to see if any have subsequently been updated. This is done so that
            # we can use a partial index on `forgotten = 1` on the assumption
            # that few users will actually forget many rooms.
            #
            # Note that a room is considered "forgotten" if *all* membership
            # events for that user and room have the forgotten field set (as
            # when a user forgets a room we update all rows for that user and
            # room, not just the current one).
            sql = """
                SELECT room_id, (
                    SELECT count(*) FROM room_memberships
                    WHERE room_id = m.room_id AND user_id = m.user_id AND forgotten = 0
                ) AS count
                FROM room_memberships AS m
                WHERE user_id = ? AND forgotten = 1
                GROUP BY room_id, user_id;
            """
            txn.execute(sql, (user_id,))
            return {row[0] for row in txn if row[1] == 0}

        return self.db.runInteraction(
            "get_forgotten_rooms_for_user", _get_forgotten_rooms_for_user_txn
        )

    @defer.inlineCallbacks
    def get_rooms_user_has_been_in(self, user_id):
        """Get all rooms that the user has ever been in.

        Args:
            user_id (str)

        Returns:
            Deferred[set[str]]: Set of room IDs.
        """

        room_ids = yield self.db.simple_select_onecol(
            table="room_memberships",
            keyvalues={"membership": Membership.JOIN, "user_id": user_id},
            retcol="room_id",
            desc="get_rooms_user_has_been_in",
        )

        return set(room_ids)

    def get_membership_from_event_ids(
        self, member_event_ids: Iterable[str]
    ) -> List[dict]:
        """Get user_id and membership of a set of event IDs.
        """

        return self.db.simple_select_many_batch(
            table="room_memberships",
            column="event_id",
            iterable=member_event_ids,
            retcols=("user_id", "membership", "event_id"),
            keyvalues={},
            batch_size=500,
            desc="get_membership_from_event_ids",
        )

    async def is_local_host_in_room_ignoring_users(
        self, room_id: str, ignore_users: Collection[str]
    ) -> bool:
        """Check if there are any local users, excluding those in the given
        list, in the room.
        """

        clause, args = make_in_list_sql_clause(
            self.database_engine, "user_id", ignore_users
        )

        sql = """
            SELECT 1 FROM local_current_membership
            WHERE
                room_id = ? AND membership = ?
                AND NOT (%s)
                LIMIT 1
        """ % (
            clause,
        )

        def _is_local_host_in_room_ignoring_users_txn(txn):
            txn.execute(sql, (room_id, Membership.JOIN, *args))

            return bool(txn.fetchone())

        return await self.db.runInteraction(
            "is_local_host_in_room_ignoring_users",
            _is_local_host_in_room_ignoring_users_txn,
        )


class RoomMemberBackgroundUpdateStore(SQLBaseStore):
    def __init__(self, database: Database, db_conn, hs):
        super(RoomMemberBackgroundUpdateStore, self).__init__(database, db_conn, hs)
        self.db.updates.register_background_update_handler(
            _MEMBERSHIP_PROFILE_UPDATE_NAME, self._background_add_membership_profile
        )
        self.db.updates.register_background_update_handler(
            _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME,
            self._background_current_state_membership,
        )
        self.db.updates.register_background_index_update(
            "room_membership_forgotten_idx",
            index_name="room_memberships_user_room_forgotten",
            table="room_memberships",
            columns=["user_id", "room_id"],
            where_clause="forgotten = 1",
        )

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
            sql = """
                SELECT stream_ordering, event_id, events.room_id, event_json.json
                FROM events
                INNER JOIN event_json USING (event_id)
                INNER JOIN room_memberships USING (event_id)
                WHERE ? <= stream_ordering AND stream_ordering < ?
                AND type = 'm.room.member'
                ORDER BY stream_ordering DESC
                LIMIT ?
            """

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = self.db.cursor_to_dict(txn)
            if not rows:
                return 0

            min_stream_id = rows[-1]["stream_ordering"]

            to_update = []
            for row in rows:
                event_id = row["event_id"]
                room_id = row["room_id"]
                try:
                    event_json = json.loads(row["json"])
                    content = event_json["content"]
                except Exception:
                    continue

                display_name = content.get("displayname", None)
                avatar_url = content.get("avatar_url", None)

                if display_name or avatar_url:
                    to_update.append((display_name, avatar_url, event_id, room_id))

            to_update_sql = """
                UPDATE room_memberships SET display_name = ?, avatar_url = ?
                WHERE event_id = ? AND room_id = ?
            """
            for index in range(0, len(to_update), INSERT_CLUMP_SIZE):
                clump = to_update[index : index + INSERT_CLUMP_SIZE]
                txn.executemany(to_update_sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
            }

            self.db.updates._background_update_progress_txn(
                txn, _MEMBERSHIP_PROFILE_UPDATE_NAME, progress
            )

            return len(rows)

        result = yield self.db.runInteraction(
            _MEMBERSHIP_PROFILE_UPDATE_NAME, add_membership_profile_txn
        )

        if not result:
            yield self.db.updates._end_background_update(
                _MEMBERSHIP_PROFILE_UPDATE_NAME
            )

        return result

    @defer.inlineCallbacks
    def _background_current_state_membership(self, progress, batch_size):
        """Update the new membership column on current_state_events.

        This works by iterating over all rooms in alphebetical order.
        """

        def _background_current_state_membership_txn(txn, last_processed_room):
            processed = 0
            while processed < batch_size:
                txn.execute(
                    """
                        SELECT MIN(room_id) FROM current_state_events WHERE room_id > ?
                    """,
                    (last_processed_room,),
                )
                row = txn.fetchone()
                if not row or not row[0]:
                    return processed, True

                (next_room,) = row

                sql = """
                    UPDATE current_state_events
                    SET membership = (
                        SELECT membership FROM room_memberships
                        WHERE event_id = current_state_events.event_id
                    )
                    WHERE room_id = ?
                """
                txn.execute(sql, (next_room,))
                processed += txn.rowcount

                last_processed_room = next_room

            self.db.updates._background_update_progress_txn(
                txn,
                _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME,
                {"last_processed_room": last_processed_room},
            )

            return processed, False

        # If we haven't got a last processed room then just use the empty
        # string, which will compare before all room IDs correctly.
        last_processed_room = progress.get("last_processed_room", "")

        row_count, finished = yield self.db.runInteraction(
            "_background_current_state_membership_update",
            _background_current_state_membership_txn,
            last_processed_room,
        )

        if finished:
            yield self.db.updates._end_background_update(
                _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME
            )

        return row_count


class RoomMemberStore(RoomMemberWorkerStore, RoomMemberBackgroundUpdateStore):
    def __init__(self, database: Database, db_conn, hs):
        super(RoomMemberStore, self).__init__(database, db_conn, hs)

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

            self._invalidate_cache_and_stream(txn, self.did_forget, (user_id, room_id))
            self._invalidate_cache_and_stream(
                txn, self.get_forgotten_rooms_for_user, (user_id,)
            )

        return self.db.runInteraction("forget_membership", f)


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
            return frozenset(self.hosts_to_joined_users)

        with (yield self.linearizer.queue(())):
            if state_entry.state_group == self.state_group:
                pass
            elif state_entry.prev_group == self.state_group:
                for (typ, state_key), event_id in iteritems(state_entry.delta_ids):
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
                    self.room_id, state_entry
                )

                self.hosts_to_joined_users = {}
                for user_id in joined_users:
                    host = intern_string(get_domain_from_id(user_id))
                    self.hosts_to_joined_users.setdefault(host, set()).add(user_id)

            if state_entry.state_group:
                self.state_group = state_entry.state_group
            else:
                self.state_group = object()
            self._len = sum(len(v) for v in itervalues(self.hosts_to_joined_users))
        return frozenset(self.hosts_to_joined_users)

    def __len__(self):
        return self._len

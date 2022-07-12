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
from typing import (
    TYPE_CHECKING,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

import attr

from synapse.api.constants import EventTypes, Membership
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import (
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.storage._base import SQLBaseStore, db_to_json, make_in_list_sql_clause
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.engines import Sqlite3Engine
from synapse.storage.roommember import (
    GetRoomsForUserWithStreamOrdering,
    MemberSummary,
    ProfileInfo,
    RoomsForUser,
)
from synapse.types import JsonDict, PersistedEventPosition, StateMap, get_domain_from_id
from synapse.util.async_helpers import Linearizer
from synapse.util.caches import intern_string
from synapse.util.caches.descriptors import _CacheContext, cached, cachedList
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.state import _StateCacheEntry

logger = logging.getLogger(__name__)


_MEMBERSHIP_PROFILE_UPDATE_NAME = "room_membership_profile_update"
_CURRENT_STATE_MEMBERSHIP_UPDATE_NAME = "current_state_events_membership"


@attr.s(frozen=True, slots=True, auto_attribs=True)
class EventIdMembership:
    """Returned by `get_membership_from_event_ids`"""

    user_id: str
    membership: str


class RoomMemberWorkerStore(EventsWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Used by `_get_joined_hosts` to ensure only one thing mutates the cache
        # at a time. Keyed by room_id.
        self._joined_host_linearizer = Linearizer("_JoinedHostsCache")

        # Is the current_state_events.membership up to date? Or is the
        # background update still running?
        self._current_state_events_membership_up_to_date = False

        txn = db_conn.cursor(
            txn_name="_check_safe_current_state_events_membership_updated"
        )
        self._check_safe_current_state_events_membership_updated_txn(txn)
        txn.close()

        if (
            self.hs.config.worker.run_background_tasks
            and self.hs.config.metrics.metrics_flags.known_servers
        ):
            self._known_servers_count = 1
            self.hs.get_clock().looping_call(
                self._count_known_servers,
                60 * 1000,
            )
            self.hs.get_clock().call_later(
                1,
                self._count_known_servers,
            )
            LaterGauge(
                "synapse_federation_known_servers",
                "",
                [],
                lambda: self._known_servers_count,
            )

    @wrap_as_background_process("_count_known_servers")
    async def _count_known_servers(self) -> int:
        """
        Count the servers that this server knows about.

        The statistic is stored on the class for the
        `synapse_federation_known_servers` LaterGauge to collect.
        """

        def _transact(txn: LoggingTransaction) -> int:
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

        count = await self.db_pool.runInteraction("get_known_servers", _transact)

        # We always know about ourselves, even if we have nothing in
        # room_memberships (for example, the server is new).
        self._known_servers_count = max([count, 1])
        return self._known_servers_count

    def _check_safe_current_state_events_membership_updated_txn(
        self, txn: LoggingTransaction
    ) -> None:
        """Checks if it is safe to assume the new current_state_events
        membership column is up to date
        """

        pending_update = self.db_pool.simple_select_one_txn(
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
                self.db_pool.runInteraction,
                "_check_safe_current_state_events_membership_updated",
                self._check_safe_current_state_events_membership_updated_txn,
            )

    @cached(max_entries=100000, iterable=True, prune_unread_entries=False)
    async def get_users_in_room(self, room_id: str) -> List[str]:
        return await self.db_pool.runInteraction(
            "get_users_in_room", self.get_users_in_room_txn, room_id
        )

    def get_users_in_room_txn(self, txn: LoggingTransaction, room_id: str) -> List[str]:
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

    @cached()
    def get_user_in_room_with_profile(
        self, room_id: str, user_id: str
    ) -> Dict[str, ProfileInfo]:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="get_user_in_room_with_profile", list_name="user_ids"
    )
    async def get_subset_users_in_room_with_profiles(
        self, room_id: str, user_ids: Collection[str]
    ) -> Dict[str, ProfileInfo]:
        """Get a mapping from user ID to profile information for a list of users
        in a given room.

        The profile information comes directly from this room's `m.room.member`
        events, and so may be specific to this room rather than part of a user's
        global profile. To avoid privacy leaks, the profile data should only be
        revealed to users who are already in this room.

        Args:
            room_id: The ID of the room to retrieve the users of.
            user_ids: a list of users in the room to run the query for

        Returns:
                A mapping from user ID to ProfileInfo.
        """

        def _get_subset_users_in_room_with_profiles(
            txn: LoggingTransaction,
        ) -> Dict[str, ProfileInfo]:
            clause, ids = make_in_list_sql_clause(
                self.database_engine, "m.user_id", user_ids
            )

            sql = """
                SELECT state_key, display_name, avatar_url FROM room_memberships as m
                INNER JOIN current_state_events as c
                ON m.event_id = c.event_id
                AND m.room_id = c.room_id
                AND m.user_id = c.state_key
                WHERE c.type = 'm.room.member' AND c.room_id = ? AND m.membership = ? AND %s
            """ % (
                clause,
            )
            txn.execute(sql, (room_id, Membership.JOIN, *ids))

            return {r[0]: ProfileInfo(display_name=r[1], avatar_url=r[2]) for r in txn}

        return await self.db_pool.runInteraction(
            "get_subset_users_in_room_with_profiles",
            _get_subset_users_in_room_with_profiles,
        )

    @cached(max_entries=100000, iterable=True)
    async def get_users_in_room_with_profiles(
        self, room_id: str
    ) -> Dict[str, ProfileInfo]:
        """Get a mapping from user ID to profile information for all users in a given room.

        The profile information comes directly from this room's `m.room.member`
        events, and so may be specific to this room rather than part of a user's
        global profile. To avoid privacy leaks, the profile data should only be
        revealed to users who are already in this room.

        Args:
            room_id: The ID of the room to retrieve the users of.

        Returns:
            A mapping from user ID to ProfileInfo.
        """

        def _get_users_in_room_with_profiles(
            txn: LoggingTransaction,
        ) -> Dict[str, ProfileInfo]:
            sql = """
                SELECT state_key, display_name, avatar_url FROM room_memberships as m
                INNER JOIN current_state_events as c
                ON m.event_id = c.event_id
                AND m.room_id = c.room_id
                AND m.user_id = c.state_key
                WHERE c.type = 'm.room.member' AND c.room_id = ? AND m.membership = ?
            """
            txn.execute(sql, (room_id, Membership.JOIN))

            return {r[0]: ProfileInfo(display_name=r[1], avatar_url=r[2]) for r in txn}

        return await self.db_pool.runInteraction(
            "get_users_in_room_with_profiles",
            _get_users_in_room_with_profiles,
        )

    @cached(max_entries=100000)
    async def get_room_summary(self, room_id: str) -> Dict[str, MemberSummary]:
        """Get the details of a room roughly suitable for use by the room
        summary extension to /sync. Useful when lazy loading room members.
        Args:
            room_id: The room ID to query
        Returns:
            dict of membership states, pointing to a MemberSummary named tuple.
        """

        def _get_room_summary_txn(
            txn: LoggingTransaction,
        ) -> Dict[str, MemberSummary]:
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
            res: Dict[str, MemberSummary] = {}
            for count, membership in txn:
                res.setdefault(membership, MemberSummary([], count))

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

        return await self.db_pool.runInteraction(
            "get_room_summary", _get_room_summary_txn
        )

    @cached()
    async def get_number_joined_users_in_room(self, room_id: str) -> int:
        return await self.db_pool.simple_select_one_onecol(
            table="current_state_events",
            keyvalues={"room_id": room_id, "membership": Membership.JOIN},
            retcol="COUNT(*)",
            desc="get_number_joined_users_in_room",
        )

    @cached()
    async def get_invited_rooms_for_local_user(
        self, user_id: str
    ) -> List[RoomsForUser]:
        """Get all the rooms the *local* user is invited to.

        Args:
            user_id: The user ID.

        Returns:
            A list of RoomsForUser.
        """

        return await self.get_rooms_for_local_user_where_membership_is(
            user_id, [Membership.INVITE]
        )

    async def get_invite_for_local_user_in_room(
        self, user_id: str, room_id: str
    ) -> Optional[RoomsForUser]:
        """Gets the invite for the given *local* user and room.

        Args:
            user_id: The user ID to find the invite of.
            room_id: The room to user was invited to.

        Returns:
            Either a RoomsForUser or None if no invite was found.
        """
        invites = await self.get_invited_rooms_for_local_user(user_id)
        for invite in invites:
            if invite.room_id == room_id:
                return invite
        return None

    async def get_rooms_for_local_user_where_membership_is(
        self,
        user_id: str,
        membership_list: Collection[str],
        excluded_rooms: Optional[List[str]] = None,
    ) -> List[RoomsForUser]:
        """Get all the rooms for this *local* user where the membership for this user
        matches one in the membership list.

        Filters out forgotten rooms.

        Args:
            user_id: The user ID.
            membership_list: A list of synapse.api.constants.Membership
                values which the user must be in.
            excluded_rooms: A list of rooms to ignore.

        Returns:
            The RoomsForUser that the user matches the membership types.
        """
        if not membership_list:
            return []

        rooms = await self.db_pool.runInteraction(
            "get_rooms_for_local_user_where_membership_is",
            self._get_rooms_for_local_user_where_membership_is_txn,
            user_id,
            membership_list,
        )

        # Now we filter out forgotten and excluded rooms
        rooms_to_exclude: Set[str] = await self.get_forgotten_rooms_for_user(user_id)

        if excluded_rooms is not None:
            rooms_to_exclude.update(set(excluded_rooms))

        return [room for room in rooms if room.room_id not in rooms_to_exclude]

    def _get_rooms_for_local_user_where_membership_is_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        membership_list: List[str],
    ) -> List[RoomsForUser]:
        """Get all the rooms for this *local* user where the membership for this user
        matches one in the membership list.

        Args:
            user_id: The user ID.
            membership_list: A list of synapse.api.constants.Membership
                    values which the user must be in.

        Returns:
            The RoomsForUser that the user matches the membership types.
        """
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
            SELECT room_id, e.sender, c.membership, event_id, e.stream_ordering, r.room_version
            FROM local_current_membership AS c
            INNER JOIN events AS e USING (room_id, event_id)
            INNER JOIN rooms AS r USING (room_id)
            WHERE
                user_id = ?
                AND %s
        """ % (
            clause,
        )

        txn.execute(sql, (user_id, *args))
        results = [RoomsForUser(*r) for r in txn]

        return results

    @cached(iterable=True)
    async def get_local_users_in_room(self, room_id: str) -> List[str]:
        """
        Retrieves a list of the current roommembers who are local to the server.
        """
        return await self.db_pool.simple_select_onecol(
            table="local_current_membership",
            keyvalues={"room_id": room_id, "membership": Membership.JOIN},
            retcol="user_id",
            desc="get_local_users_in_room",
        )

    async def get_local_current_membership_for_user_in_room(
        self, user_id: str, room_id: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Retrieve the current local membership state and event ID for a user in a room.

        Args:
            user_id: The ID of the user.
            room_id: The ID of the room.

        Returns:
            A tuple of (membership_type, event_id). Both will be None if a
                room_id/user_id pair is not found.
        """
        # Paranoia check.
        if not self.hs.is_mine_id(user_id):
            raise Exception(
                "Cannot call 'get_local_current_membership_for_user_in_room' on "
                "non-local user %s" % (user_id,),
            )

        results_dict = await self.db_pool.simple_select_one(
            "local_current_membership",
            {"room_id": room_id, "user_id": user_id},
            ("membership", "event_id"),
            allow_none=True,
            desc="get_local_current_membership_for_user_in_room",
        )
        if not results_dict:
            return None, None

        return results_dict.get("membership"), results_dict.get("event_id")

    @cached(max_entries=500000, iterable=True, prune_unread_entries=False)
    async def get_rooms_for_user_with_stream_ordering(
        self, user_id: str
    ) -> FrozenSet[GetRoomsForUserWithStreamOrdering]:
        """Returns a set of room_ids the user is currently joined to.

        If a remote user only returns rooms this server is currently
        participating in.

        Args:
            user_id

        Returns:
            Returns the rooms the user is in currently, along with the stream
            ordering of the most recent join for that user and room, along with
            the room version of the room.
        """
        return await self.db_pool.runInteraction(
            "get_rooms_for_user_with_stream_ordering",
            self._get_rooms_for_user_with_stream_ordering_txn,
            user_id,
        )

    def _get_rooms_for_user_with_stream_ordering_txn(
        self, txn: LoggingTransaction, user_id: str
    ) -> FrozenSet[GetRoomsForUserWithStreamOrdering]:
        # We use `current_state_events` here and not `local_current_membership`
        # as a) this gets called with remote users and b) this only gets called
        # for rooms the server is participating in.
        if self._current_state_events_membership_up_to_date:
            sql = """
                SELECT room_id, e.instance_name, e.stream_ordering
                FROM current_state_events AS c
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    c.type = 'm.room.member'
                    AND c.state_key = ?
                    AND c.membership = ?
            """
        else:
            sql = """
                SELECT room_id, e.instance_name, e.stream_ordering
                FROM current_state_events AS c
                INNER JOIN room_memberships AS m USING (room_id, event_id)
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    c.type = 'm.room.member'
                    AND c.state_key = ?
                    AND m.membership = ?
            """

        txn.execute(sql, (user_id, Membership.JOIN))
        return frozenset(
            GetRoomsForUserWithStreamOrdering(
                room_id, PersistedEventPosition(instance, stream_id)
            )
            for room_id, instance, stream_id in txn
        )

    @cachedList(
        cached_method_name="get_rooms_for_user_with_stream_ordering",
        list_name="user_ids",
    )
    async def get_rooms_for_users_with_stream_ordering(
        self, user_ids: Collection[str]
    ) -> Dict[str, FrozenSet[GetRoomsForUserWithStreamOrdering]]:
        """A batched version of `get_rooms_for_user_with_stream_ordering`.

        Returns:
            Map from user_id to set of rooms that is currently in.
        """
        return await self.db_pool.runInteraction(
            "get_rooms_for_users_with_stream_ordering",
            self._get_rooms_for_users_with_stream_ordering_txn,
            user_ids,
        )

    def _get_rooms_for_users_with_stream_ordering_txn(
        self, txn: LoggingTransaction, user_ids: Collection[str]
    ) -> Dict[str, FrozenSet[GetRoomsForUserWithStreamOrdering]]:

        clause, args = make_in_list_sql_clause(
            self.database_engine,
            "c.state_key",
            user_ids,
        )

        if self._current_state_events_membership_up_to_date:
            sql = f"""
                SELECT c.state_key, room_id, e.instance_name, e.stream_ordering
                FROM current_state_events AS c
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    c.type = 'm.room.member'
                    AND c.membership = ?
                    AND {clause}
            """
        else:
            sql = f"""
                SELECT c.state_key, room_id, e.instance_name, e.stream_ordering
                FROM current_state_events AS c
                INNER JOIN room_memberships AS m USING (room_id, event_id)
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    c.type = 'm.room.member'
                    AND m.membership = ?
                    AND {clause}
            """

        txn.execute(sql, [Membership.JOIN] + args)

        result: Dict[str, Set[GetRoomsForUserWithStreamOrdering]] = {
            user_id: set() for user_id in user_ids
        }
        for user_id, room_id, instance, stream_id in txn:
            result[user_id].add(
                GetRoomsForUserWithStreamOrdering(
                    room_id, PersistedEventPosition(instance, stream_id)
                )
            )

        return {user_id: frozenset(v) for user_id, v in result.items()}

    async def get_users_server_still_shares_room_with(
        self, user_ids: Collection[str]
    ) -> Set[str]:
        """Given a list of users return the set that the server still share a
        room with.
        """

        if not user_ids:
            return set()

        def _get_users_server_still_shares_room_with_txn(
            txn: LoggingTransaction,
        ) -> Set[str]:
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

        return await self.db_pool.runInteraction(
            "get_users_server_still_shares_room_with",
            _get_users_server_still_shares_room_with_txn,
        )

    async def get_rooms_for_user(
        self, user_id: str, on_invalidate: Optional[Callable[[], None]] = None
    ) -> FrozenSet[str]:
        """Returns a set of room_ids the user is currently joined to.

        If a remote user only returns rooms this server is currently
        participating in.
        """
        rooms = await self.get_rooms_for_user_with_stream_ordering(
            user_id, on_invalidate=on_invalidate
        )
        return frozenset(r.room_id for r in rooms)

    @cached(
        max_entries=500000,
        cache_context=True,
        iterable=True,
        prune_unread_entries=False,
    )
    async def get_users_who_share_room_with_user(
        self, user_id: str, cache_context: _CacheContext
    ) -> Set[str]:
        """Returns the set of users who share a room with `user_id`"""
        room_ids = await self.get_rooms_for_user(
            user_id, on_invalidate=cache_context.invalidate
        )

        user_who_share_room = set()
        for room_id in room_ids:
            user_ids = await self.get_users_in_room(
                room_id, on_invalidate=cache_context.invalidate
            )
            user_who_share_room.update(user_ids)

        return user_who_share_room

    @cached(cache_context=True, iterable=True)
    async def get_mutual_rooms_between_users(
        self, user_ids: FrozenSet[str], cache_context: _CacheContext
    ) -> FrozenSet[str]:
        """
        Returns the set of rooms that all users in `user_ids` share.

        Args:
            user_ids: A frozen set of all users to investigate and return
              overlapping joined rooms for.
            cache_context
        """
        shared_room_ids: Optional[FrozenSet[str]] = None
        for user_id in user_ids:
            room_ids = await self.get_rooms_for_user(
                user_id, on_invalidate=cache_context.invalidate
            )
            if shared_room_ids is not None:
                shared_room_ids &= room_ids
            else:
                shared_room_ids = room_ids

        return shared_room_ids or frozenset()

    async def get_joined_users_from_context(
        self, event: EventBase, context: EventContext
    ) -> Dict[str, ProfileInfo]:
        state_group: Union[object, int] = context.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        current_state_ids = await context.get_current_state_ids()
        assert current_state_ids is not None
        assert state_group is not None
        return await self._get_joined_users_from_context(
            event.room_id, state_group, current_state_ids, event=event, context=context
        )

    async def get_joined_users_from_state(
        self, room_id: str, state_entry: "_StateCacheEntry"
    ) -> Dict[str, ProfileInfo]:
        state_group: Union[object, int] = state_entry.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        assert state_group is not None
        with Measure(self._clock, "get_joined_users_from_state"):
            return await self._get_joined_users_from_context(
                room_id, state_group, state_entry.state, context=state_entry
            )

    @cached(num_args=2, cache_context=True, iterable=True, max_entries=100000)
    async def _get_joined_users_from_context(
        self,
        room_id: str,
        state_group: Union[object, int],
        current_state_ids: StateMap[str],
        cache_context: _CacheContext,
        event: Optional[EventBase] = None,
        context: Optional[Union[EventContext, "_StateCacheEntry"]] = None,
    ) -> Dict[str, ProfileInfo]:
        # We don't use `state_group`, it's there so that we can cache based
        # on it. However, it's important that it's never None, since two current_states
        # with a state_group of None are likely to be different.
        assert state_group is not None

        users_in_room = {}
        member_event_ids = [
            e_id
            for key, e_id in current_state_ids.items()
            if key[0] == EventTypes.Member
        ]

        if context is not None:
            # If we have a context with a delta from a previous state group,
            # check if we also have the result from the previous group in cache.
            # If we do then we can reuse that result and simply update it with
            # any membership changes in `delta_ids`
            if context.prev_group and context.delta_ids:
                prev_res = self._get_joined_users_from_context.cache.get_immediate(
                    (room_id, context.prev_group), None
                )
                if prev_res and isinstance(prev_res, dict):
                    users_in_room = dict(prev_res)
                    member_event_ids = [
                        e_id
                        for key, e_id in context.delta_ids.items()
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
        event_map = self._get_events_from_cache(member_event_ids, update_metrics=False)

        missing_member_event_ids = []
        for event_id in member_event_ids:
            ev_entry = event_map.get(event_id)
            if ev_entry and not ev_entry.event.rejected_reason:
                if ev_entry.event.membership == Membership.JOIN:
                    users_in_room[ev_entry.event.state_key] = ProfileInfo(
                        display_name=ev_entry.event.content.get("displayname", None),
                        avatar_url=ev_entry.event.content.get("avatar_url", None),
                    )
            else:
                missing_member_event_ids.append(event_id)

        if missing_member_event_ids:
            event_to_memberships = await self._get_joined_profiles_from_event_ids(
                missing_member_event_ids
            )
            users_in_room.update(row for row in event_to_memberships.values() if row)

        if event is not None and event.type == EventTypes.Member:
            if event.membership == Membership.JOIN:
                if event.event_id in member_event_ids:
                    users_in_room[event.state_key] = ProfileInfo(
                        display_name=event.content.get("displayname", None),
                        avatar_url=event.content.get("avatar_url", None),
                    )

        return users_in_room

    @cached(max_entries=10000)
    def _get_joined_profile_from_event_id(
        self, event_id: str
    ) -> Optional[Tuple[str, ProfileInfo]]:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_joined_profile_from_event_id",
        list_name="event_ids",
    )
    async def _get_joined_profiles_from_event_ids(
        self, event_ids: Iterable[str]
    ) -> Dict[str, Optional[Tuple[str, ProfileInfo]]]:
        """For given set of member event_ids check if they point to a join
        event and if so return the associated user and profile info.

        Args:
            event_ids: The member event IDs to lookup

        Returns:
            Map from event ID to `user_id` and ProfileInfo (or None if not join event).
        """

        rows = await self.db_pool.simple_select_many_batch(
            table="room_memberships",
            column="event_id",
            iterable=event_ids,
            retcols=("user_id", "display_name", "avatar_url", "event_id"),
            keyvalues={"membership": Membership.JOIN},
            batch_size=500,
            desc="_get_joined_profiles_from_event_ids",
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

    @cached(max_entries=10000)
    async def is_host_joined(self, room_id: str, host: str) -> bool:
        return await self._check_host_room_membership(room_id, host, Membership.JOIN)

    @cached(max_entries=10000)
    async def is_host_invited(self, room_id: str, host: str) -> bool:
        return await self._check_host_room_membership(room_id, host, Membership.INVITE)

    async def _check_host_room_membership(
        self, room_id: str, host: str, membership: str
    ) -> bool:
        if "%" in host or "_" in host:
            raise Exception("Invalid host name")

        sql = """
            SELECT state_key FROM current_state_events AS c
            INNER JOIN room_memberships AS m USING (event_id)
            WHERE m.membership = ?
                AND type = 'm.room.member'
                AND c.room_id = ?
                AND state_key LIKE ?
            LIMIT 1
        """

        # We do need to be careful to ensure that host doesn't have any wild cards
        # in it, but we checked above for known ones and we'll check below that
        # the returned user actually has the correct domain.
        like_clause = "%:" + host

        rows = await self.db_pool.execute(
            "is_host_joined", None, sql, membership, room_id, like_clause
        )

        if not rows:
            return False

        user_id = rows[0][0]
        if get_domain_from_id(user_id) != host:
            # This can only happen if the host name has something funky in it
            raise Exception("Invalid host name")

        return True

    @cached(iterable=True, max_entries=10000)
    async def get_current_hosts_in_room(self, room_id: str) -> Set[str]:
        """Get current hosts in room based on current state."""

        # First we check if we already have `get_users_in_room` in the cache, as
        # we can just calculate result from that
        users = self.get_users_in_room.cache.get_immediate(
            (room_id,), None, update_metrics=False
        )
        if users is not None:
            return {get_domain_from_id(u) for u in users}

        if isinstance(self.database_engine, Sqlite3Engine):
            # If we're using SQLite then let's just always use
            # `get_users_in_room` rather than funky SQL.
            users = await self.get_users_in_room(room_id)
            return {get_domain_from_id(u) for u in users}

        # For PostgreSQL we can use a regex to pull out the domains from the
        # joined users in `current_state_events` via regex.

        def get_current_hosts_in_room_txn(txn: LoggingTransaction) -> Set[str]:
            sql = """
                SELECT DISTINCT substring(state_key FROM '@[^:]*:(.*)$')
                FROM current_state_events
                WHERE
                    type = 'm.room.member'
                    AND membership = 'join'
                    AND room_id = ?
            """
            txn.execute(sql, (room_id,))
            return {d for d, in txn}

        return await self.db_pool.runInteraction(
            "get_current_hosts_in_room", get_current_hosts_in_room_txn
        )

    async def get_joined_hosts(
        self, room_id: str, state_entry: "_StateCacheEntry"
    ) -> FrozenSet[str]:
        state_group: Union[object, int] = state_entry.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        assert state_group is not None
        with Measure(self._clock, "get_joined_hosts"):
            return await self._get_joined_hosts(
                room_id, state_group, state_entry=state_entry
            )

    @cached(num_args=2, max_entries=10000, iterable=True)
    async def _get_joined_hosts(
        self,
        room_id: str,
        state_group: Union[object, int],
        state_entry: "_StateCacheEntry",
    ) -> FrozenSet[str]:
        # We don't use `state_group`, it's there so that we can cache based on
        # it. However, its important that its never None, since two
        # current_state's with a state_group of None are likely to be different.
        #
        # The `state_group` must match the `state_entry.state_group` (if not None).
        assert state_group is not None
        assert state_entry.state_group is None or state_entry.state_group == state_group

        # We use a secondary cache of previous work to allow us to build up the
        # joined hosts for the given state group based on previous state groups.
        #
        # We cache one object per room containing the results of the last state
        # group we got joined hosts for. The idea is that generally
        # `get_joined_hosts` is called with the "current" state group for the
        # room, and so consecutive calls will be for consecutive state groups
        # which point to the previous state group.
        cache = await self._get_joined_hosts_cache(room_id)  # type: ignore[misc]

        # If the state group in the cache matches, we already have the data we need.
        if state_entry.state_group == cache.state_group:
            return frozenset(cache.hosts_to_joined_users)

        # Since we'll mutate the cache we need to lock.
        async with self._joined_host_linearizer.queue(room_id):
            if state_entry.state_group == cache.state_group:
                # Same state group, so nothing to do. We've already checked for
                # this above, but the cache may have changed while waiting on
                # the lock.
                pass
            elif state_entry.prev_group == cache.state_group:
                # The cached work is for the previous state group, so we work out
                # the delta.
                assert state_entry.delta_ids is not None
                for (typ, state_key), event_id in state_entry.delta_ids.items():
                    if typ != EventTypes.Member:
                        continue

                    host = intern_string(get_domain_from_id(state_key))
                    user_id = state_key
                    known_joins = cache.hosts_to_joined_users.setdefault(host, set())

                    event = await self.get_event(event_id)
                    if event.membership == Membership.JOIN:
                        known_joins.add(user_id)
                    else:
                        known_joins.discard(user_id)

                        if not known_joins:
                            cache.hosts_to_joined_users.pop(host, None)
            else:
                # The cache doesn't match the state group or prev state group,
                # so we calculate the result from first principles.
                joined_users = await self.get_joined_users_from_state(
                    room_id, state_entry
                )

                cache.hosts_to_joined_users = {}
                for user_id in joined_users:
                    host = intern_string(get_domain_from_id(user_id))
                    cache.hosts_to_joined_users.setdefault(host, set()).add(user_id)

            if state_entry.state_group:
                cache.state_group = state_entry.state_group
            else:
                cache.state_group = object()

        return frozenset(cache.hosts_to_joined_users)

    @cached(max_entries=10000)
    def _get_joined_hosts_cache(self, room_id: str) -> "_JoinedHostsCache":
        return _JoinedHostsCache()

    @cached(num_args=2)
    async def did_forget(self, user_id: str, room_id: str) -> bool:
        """Returns whether user_id has elected to discard history for room_id.

        Returns False if they have since re-joined."""

        def f(txn: LoggingTransaction) -> int:
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

        count = await self.db_pool.runInteraction("did_forget_membership", f)
        return count == 0

    @cached()
    async def get_forgotten_rooms_for_user(self, user_id: str) -> Set[str]:
        """Gets all rooms the user has forgotten.

        Args:
            user_id: The user ID to query the rooms of.

        Returns:
            The forgotten rooms.
        """

        def _get_forgotten_rooms_for_user_txn(txn: LoggingTransaction) -> Set[str]:
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

        return await self.db_pool.runInteraction(
            "get_forgotten_rooms_for_user", _get_forgotten_rooms_for_user_txn
        )

    async def get_rooms_user_has_been_in(self, user_id: str) -> Set[str]:
        """Get all rooms that the user has ever been in.

        Args:
            user_id: The user ID to get the rooms of.

        Returns:
            Set of room IDs.
        """

        room_ids = await self.db_pool.simple_select_onecol(
            table="room_memberships",
            keyvalues={"membership": Membership.JOIN, "user_id": user_id},
            retcol="room_id",
            desc="get_rooms_user_has_been_in",
        )

        return set(room_ids)

    @cached(max_entries=5000)
    async def _get_membership_from_event_id(
        self, member_event_id: str
    ) -> Optional[EventIdMembership]:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_membership_from_event_id", list_name="member_event_ids"
    )
    async def get_membership_from_event_ids(
        self, member_event_ids: Iterable[str]
    ) -> Dict[str, Optional[EventIdMembership]]:
        """Get user_id and membership of a set of event IDs.

        Returns:
            Mapping from event ID to `EventIdMembership` if the event is a
            membership event, otherwise the value is None.
        """

        rows = await self.db_pool.simple_select_many_batch(
            table="room_memberships",
            column="event_id",
            iterable=member_event_ids,
            retcols=("user_id", "membership", "event_id"),
            keyvalues={},
            batch_size=500,
            desc="get_membership_from_event_ids",
        )

        return {
            row["event_id"]: EventIdMembership(
                membership=row["membership"], user_id=row["user_id"]
            )
            for row in rows
        }

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

        def _is_local_host_in_room_ignoring_users_txn(
            txn: LoggingTransaction,
        ) -> bool:
            txn.execute(sql, (room_id, Membership.JOIN, *args))

            return bool(txn.fetchone())

        return await self.db_pool.runInteraction(
            "is_local_host_in_room_ignoring_users",
            _is_local_host_in_room_ignoring_users_txn,
        )


class RoomMemberBackgroundUpdateStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)
        self.db_pool.updates.register_background_update_handler(
            _MEMBERSHIP_PROFILE_UPDATE_NAME, self._background_add_membership_profile
        )
        self.db_pool.updates.register_background_update_handler(
            _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME,
            self._background_current_state_membership,
        )
        self.db_pool.updates.register_background_index_update(
            "room_membership_forgotten_idx",
            index_name="room_memberships_user_room_forgotten",
            table="room_memberships",
            columns=["user_id", "room_id"],
            where_clause="forgotten = 1",
        )

    async def _background_add_membership_profile(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        target_min_stream_id = progress.get(
            "target_min_stream_id_inclusive", self._min_stream_order_on_start  # type: ignore[attr-defined]
        )
        max_stream_id = progress.get(
            "max_stream_id_exclusive", self._stream_order_on_start + 1  # type: ignore[attr-defined]
        )

        def add_membership_profile_txn(txn: LoggingTransaction) -> int:
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

            rows = self.db_pool.cursor_to_dict(txn)
            if not rows:
                return 0

            min_stream_id = rows[-1]["stream_ordering"]

            to_update = []
            for row in rows:
                event_id = row["event_id"]
                room_id = row["room_id"]
                try:
                    event_json = db_to_json(row["json"])
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
            txn.execute_batch(to_update_sql, to_update)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
            }

            self.db_pool.updates._background_update_progress_txn(
                txn, _MEMBERSHIP_PROFILE_UPDATE_NAME, progress
            )

            return len(rows)

        result = await self.db_pool.runInteraction(
            _MEMBERSHIP_PROFILE_UPDATE_NAME, add_membership_profile_txn
        )

        if not result:
            await self.db_pool.updates._end_background_update(
                _MEMBERSHIP_PROFILE_UPDATE_NAME
            )

        return result

    async def _background_current_state_membership(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Update the new membership column on current_state_events.

        This works by iterating over all rooms in alphebetical order.
        """

        def _background_current_state_membership_txn(
            txn: LoggingTransaction, last_processed_room: str
        ) -> Tuple[int, bool]:
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

            self.db_pool.updates._background_update_progress_txn(
                txn,
                _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME,
                {"last_processed_room": last_processed_room},
            )

            return processed, False

        # If we haven't got a last processed room then just use the empty
        # string, which will compare before all room IDs correctly.
        last_processed_room = progress.get("last_processed_room", "")

        row_count, finished = await self.db_pool.runInteraction(
            "_background_current_state_membership_update",
            _background_current_state_membership_txn,
            last_processed_room,
        )

        if finished:
            await self.db_pool.updates._end_background_update(
                _CURRENT_STATE_MEMBERSHIP_UPDATE_NAME
            )

        return row_count


class RoomMemberStore(
    RoomMemberWorkerStore,
    RoomMemberBackgroundUpdateStore,
    CacheInvalidationWorkerStore,
):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

    async def forget(self, user_id: str, room_id: str) -> None:
        """Indicate that user_id wishes to discard history for room_id."""

        def f(txn: LoggingTransaction) -> None:
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

        await self.db_pool.runInteraction("forget_membership", f)


@attr.s(slots=True, auto_attribs=True)
class _JoinedHostsCache:
    """The cached data used by the `_get_joined_hosts_cache`."""

    # Dict of host to the set of their users in the room at the state group.
    hosts_to_joined_users: Dict[str, Set[str]] = attr.Factory(dict)

    # The state group `hosts_to_joined_users` is derived from. Will be an object
    # if the instance is newly created or if the state is not based on a state
    # group. (An object is used as a sentinel value to ensure that it never is
    # equal to anything else).
    state_group: Union[object, int] = attr.Factory(object)

    def __len__(self) -> int:
        return sum(len(v) for v in self.hosts_to_joined_users.values())

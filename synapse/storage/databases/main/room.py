# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from abc import abstractmethod
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Collection,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)

import attr

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    JoinRules,
    PublicRoomsFilterFields,
)
from synapse.api.errors import StoreError
from synapse.api.room_versions import RoomVersion, RoomVersions
from synapse.config.homeserver import HomeServerConfig
from synapse.events import EventBase
from synapse.storage._base import SQLBaseStore, db_to_json, make_in_list_sql_clause
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.types import Cursor
from synapse.storage.util.id_generators import IdGenerator
from synapse.types import JsonDict, RetentionPolicy, ThirdPartyInstanceID
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached
from synapse.util.stringutils import MXC_REGEX

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class RatelimitOverride:
    messages_per_second: int
    burst_count: int


class RoomSortOrder(Enum):
    """
    Enum to define the sorting method used when returning rooms with get_rooms_paginate

    NAME = sort rooms alphabetically by name
    JOINED_MEMBERS = sort rooms by membership size, highest to lowest
    """

    # ALPHABETICAL and SIZE are deprecated.
    # ALPHABETICAL is the same as NAME.
    ALPHABETICAL = "alphabetical"
    # SIZE is the same as JOINED_MEMBERS.
    SIZE = "size"
    NAME = "name"
    CANONICAL_ALIAS = "canonical_alias"
    JOINED_MEMBERS = "joined_members"
    JOINED_LOCAL_MEMBERS = "joined_local_members"
    VERSION = "version"
    CREATOR = "creator"
    ENCRYPTION = "encryption"
    FEDERATABLE = "federatable"
    PUBLIC = "public"
    JOIN_RULES = "join_rules"
    GUEST_ACCESS = "guest_access"
    HISTORY_VISIBILITY = "history_visibility"
    STATE_EVENTS = "state_events"


class RoomWorkerStore(CacheInvalidationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.config: HomeServerConfig = hs.config

    async def store_room(
        self,
        room_id: str,
        room_creator_user_id: str,
        is_public: bool,
        room_version: RoomVersion,
    ) -> None:
        """Stores a room.

        Args:
            room_id: The desired room ID, can be None.
            room_creator_user_id: The user ID of the room creator.
            is_public: True to indicate that this room should appear in
                public room lists.
            room_version: The version of the room
        Raises:
            StoreError if the room could not be stored.
        """
        try:
            await self.db_pool.simple_insert(
                "rooms",
                {
                    "room_id": room_id,
                    "creator": room_creator_user_id,
                    "is_public": is_public,
                    "room_version": room_version.identifier,
                    "has_auth_chain_index": True,
                },
                desc="store_room",
            )
        except Exception as e:
            logger.error("store_room with room_id=%s failed: %s", room_id, e)
            raise StoreError(500, "Problem creating room.")

    async def get_room(self, room_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a room.

        Args:
            room_id: The ID of the room to retrieve.
        Returns:
            A dict containing the room information, or None if the room is unknown.
        """
        return await self.db_pool.simple_select_one(
            table="rooms",
            keyvalues={"room_id": room_id},
            retcols=("room_id", "is_public", "creator", "has_auth_chain_index"),
            desc="get_room",
            allow_none=True,
        )

    async def get_room_with_stats(self, room_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve room with statistics.

        Args:
            room_id: The ID of the room to retrieve.
        Returns:
            A dict containing the room information, or None if the room is unknown.
        """

        def get_room_with_stats_txn(
            txn: LoggingTransaction, room_id: str
        ) -> Optional[Dict[str, Any]]:
            sql = """
                SELECT room_id, state.name, state.canonical_alias, curr.joined_members,
                  curr.local_users_in_room AS joined_local_members, rooms.room_version AS version,
                  rooms.creator, state.encryption, state.is_federatable AS federatable,
                  rooms.is_public AS public, state.join_rules, state.guest_access,
                  state.history_visibility, curr.current_state_events AS state_events,
                  state.avatar, state.topic, state.room_type
                FROM rooms
                LEFT JOIN room_stats_state state USING (room_id)
                LEFT JOIN room_stats_current curr USING (room_id)
                WHERE room_id = ?
                """
            txn.execute(sql, [room_id])
            # Catch error if sql returns empty result to return "None" instead of an error
            try:
                res = self.db_pool.cursor_to_dict(txn)[0]
            except IndexError:
                return None

            res["federatable"] = bool(res["federatable"])
            res["public"] = bool(res["public"])
            return res

        return await self.db_pool.runInteraction(
            "get_room_with_stats", get_room_with_stats_txn, room_id
        )

    async def get_public_room_ids(self) -> List[str]:
        return await self.db_pool.simple_select_onecol(
            table="rooms",
            keyvalues={"is_public": True},
            retcol="room_id",
            desc="get_public_room_ids",
        )

    def _construct_room_type_where_clause(
        self, room_types: Union[List[Union[str, None]], None]
    ) -> Tuple[Union[str, None], List[str]]:
        if not room_types:
            return None, []
        else:
            # We use None when we want get rooms without a type
            is_null_clause = ""
            if None in room_types:
                is_null_clause = "OR room_type IS NULL"
                room_types = [value for value in room_types if value is not None]

            list_clause, args = make_in_list_sql_clause(
                self.database_engine, "room_type", room_types
            )

            return f"({list_clause} {is_null_clause})", args

    async def count_public_rooms(
        self,
        network_tuple: Optional[ThirdPartyInstanceID],
        ignore_non_federatable: bool,
        search_filter: Optional[dict],
    ) -> int:
        """Counts the number of public rooms as tracked in the room_stats_current
        and room_stats_state table.

        Args:
            network_tuple
            ignore_non_federatable: If true filters out non-federatable rooms
            search_filter
        """

        def _count_public_rooms_txn(txn: LoggingTransaction) -> int:
            query_args = []

            room_type_clause, args = self._construct_room_type_where_clause(
                search_filter.get(PublicRoomsFilterFields.ROOM_TYPES, None)
                if search_filter
                else None
            )
            room_type_clause = f" AND {room_type_clause}" if room_type_clause else ""
            query_args += args

            if network_tuple:
                if network_tuple.appservice_id:
                    published_sql = """
                        SELECT room_id from appservice_room_list
                        WHERE appservice_id = ? AND network_id = ?
                    """
                    query_args.append(network_tuple.appservice_id)
                    assert network_tuple.network_id is not None
                    query_args.append(network_tuple.network_id)
                else:
                    published_sql = """
                        SELECT room_id FROM rooms WHERE is_public
                    """
            else:
                published_sql = """
                    SELECT room_id FROM rooms WHERE is_public
                    UNION SELECT room_id from appservice_room_list
            """

            sql = f"""
                SELECT
                    COUNT(*)
                FROM (
                    {published_sql}
                ) published
                INNER JOIN room_stats_state USING (room_id)
                INNER JOIN room_stats_current USING (room_id)
                WHERE
                    (
                        join_rules = '{JoinRules.PUBLIC}'
                        OR join_rules = '{JoinRules.KNOCK}'
                        OR join_rules = '{JoinRules.KNOCK_RESTRICTED}'
                        OR history_visibility = 'world_readable'
                    )
                    {room_type_clause}
                    AND joined_members > 0
            """

            txn.execute(sql, query_args)
            return cast(Tuple[int], txn.fetchone())[0]

        return await self.db_pool.runInteraction(
            "count_public_rooms", _count_public_rooms_txn
        )

    async def get_room_count(self) -> int:
        """Retrieve the total number of rooms."""

        def f(txn: LoggingTransaction) -> int:
            sql = "SELECT count(*)  FROM rooms"
            txn.execute(sql)
            row = cast(Tuple[int], txn.fetchone())
            return row[0]

        return await self.db_pool.runInteraction("get_rooms", f)

    async def get_largest_public_rooms(
        self,
        network_tuple: Optional[ThirdPartyInstanceID],
        search_filter: Optional[dict],
        limit: Optional[int],
        bounds: Optional[Tuple[int, str]],
        forwards: bool,
        ignore_non_federatable: bool = False,
    ) -> List[Dict[str, Any]]:
        """Gets the largest public rooms (where largest is in terms of joined
        members, as tracked in the statistics table).

        Args:
            network_tuple
            search_filter
            limit: Maxmimum number of rows to return, unlimited otherwise.
            bounds: An uppoer or lower bound to apply to result set if given,
                consists of a joined member count and room_id (these are
                excluded from result set).
            forwards: true iff going forwards, going backwards otherwise
            ignore_non_federatable: If true filters out non-federatable rooms.

        Returns:
            Rooms in order: biggest number of joined users first.
            We then arbitrarily use the room_id as a tie breaker.

        """

        where_clauses = []
        query_args: List[Union[str, int]] = []

        if network_tuple:
            if network_tuple.appservice_id:
                published_sql = """
                    SELECT room_id from appservice_room_list
                    WHERE appservice_id = ? AND network_id = ?
                """
                query_args.append(network_tuple.appservice_id)
                assert network_tuple.network_id is not None
                query_args.append(network_tuple.network_id)
            else:
                published_sql = """
                    SELECT room_id FROM rooms WHERE is_public
                """
        else:
            published_sql = """
                SELECT room_id FROM rooms WHERE is_public
                UNION SELECT room_id from appservice_room_list
            """

        # Work out the bounds if we're given them, these bounds look slightly
        # odd, but are designed to help query planner use indices by pulling
        # out a common bound.
        if bounds:
            last_joined_members, last_room_id = bounds
            if forwards:
                where_clauses.append(
                    """
                        joined_members <= ? AND (
                            joined_members < ? OR room_id < ?
                        )
                    """
                )
            else:
                where_clauses.append(
                    """
                        joined_members >= ? AND (
                            joined_members > ? OR room_id > ?
                        )
                    """
                )

            query_args += [last_joined_members, last_joined_members, last_room_id]

        if ignore_non_federatable:
            where_clauses.append("is_federatable")

        if search_filter and search_filter.get(
            PublicRoomsFilterFields.GENERIC_SEARCH_TERM, None
        ):
            search_term = (
                "%" + search_filter[PublicRoomsFilterFields.GENERIC_SEARCH_TERM] + "%"
            )

            where_clauses.append(
                """
                    (
                        LOWER(name) LIKE ?
                        OR LOWER(topic) LIKE ?
                        OR LOWER(canonical_alias) LIKE ?
                    )
                """
            )
            query_args += [
                search_term.lower(),
                search_term.lower(),
                search_term.lower(),
            ]

        room_type_clause, args = self._construct_room_type_where_clause(
            search_filter.get(PublicRoomsFilterFields.ROOM_TYPES, None)
            if search_filter
            else None
        )
        if room_type_clause:
            where_clauses.append(room_type_clause)
        query_args += args

        where_clause = ""
        if where_clauses:
            where_clause = " AND " + " AND ".join(where_clauses)

        dir = "DESC" if forwards else "ASC"
        sql = f"""
            SELECT
                room_id, name, topic, canonical_alias, joined_members,
                avatar, history_visibility, guest_access, join_rules, room_type
            FROM (
                {published_sql}
            ) published
            INNER JOIN room_stats_state USING (room_id)
            INNER JOIN room_stats_current USING (room_id)
            WHERE
                (
                    join_rules = '{JoinRules.PUBLIC}'
                    OR join_rules = '{JoinRules.KNOCK}'
                    OR join_rules = '{JoinRules.KNOCK_RESTRICTED}'
                    OR history_visibility = 'world_readable'
                )
                AND joined_members > 0
                {where_clause}
            ORDER BY
                joined_members {dir},
                room_id {dir}
        """

        if limit is not None:
            query_args.append(limit)

            sql += """
                LIMIT ?
            """

        def _get_largest_public_rooms_txn(
            txn: LoggingTransaction,
        ) -> List[Dict[str, Any]]:
            txn.execute(sql, query_args)

            results = self.db_pool.cursor_to_dict(txn)

            if not forwards:
                results.reverse()

            return results

        ret_val = await self.db_pool.runInteraction(
            "get_largest_public_rooms", _get_largest_public_rooms_txn
        )
        return ret_val

    @cached(max_entries=10000)
    async def is_room_blocked(self, room_id: str) -> Optional[bool]:
        return await self.db_pool.simple_select_one_onecol(
            table="blocked_rooms",
            keyvalues={"room_id": room_id},
            retcol="1",
            allow_none=True,
            desc="is_room_blocked",
        )

    async def room_is_blocked_by(self, room_id: str) -> Optional[str]:
        """
        Function to retrieve user who has blocked the room.
        user_id is non-nullable
        It returns None if the room is not blocked.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="blocked_rooms",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            allow_none=True,
            desc="room_is_blocked_by",
        )

    async def get_rooms_paginate(
        self,
        start: int,
        limit: int,
        order_by: str,
        reverse_order: bool,
        search_term: Optional[str],
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Function to retrieve a paginated list of rooms as json.

        Args:
            start: offset in the list
            limit: maximum amount of rooms to retrieve
            order_by: the sort order of the returned list
            reverse_order: whether to reverse the room list
            search_term: a string to filter room names,
                canonical alias and room ids by.
                Room ID must match exactly. Canonical alias must match a substring of the local part.
        Returns:
            A list of room dicts and an integer representing the total number of
            rooms that exist given this query
        """
        # Filter room names by a string
        where_statement = ""
        search_pattern: List[object] = []
        if search_term:
            where_statement = """
                WHERE LOWER(state.name) LIKE ?
                OR LOWER(state.canonical_alias) LIKE ?
                OR state.room_id = ?
            """

            # Our postgres db driver converts ? -> %s in SQL strings as that's the
            # placeholder for postgres.
            # HOWEVER, if you put a % into your SQL then everything goes wibbly.
            # To get around this, we're going to surround search_term with %'s
            # before giving it to the database in python instead
            search_pattern = [
                "%" + search_term.lower() + "%",
                "#%" + search_term.lower() + "%:%",
                search_term,
            ]

        # Set ordering
        if RoomSortOrder(order_by) == RoomSortOrder.SIZE:
            # Deprecated in favour of RoomSortOrder.JOINED_MEMBERS
            order_by_column = "curr.joined_members"
            order_by_asc = False
        elif RoomSortOrder(order_by) == RoomSortOrder.ALPHABETICAL:
            # Deprecated in favour of RoomSortOrder.NAME
            order_by_column = "state.name"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.NAME:
            order_by_column = "state.name"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.CANONICAL_ALIAS:
            order_by_column = "state.canonical_alias"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.JOINED_MEMBERS:
            order_by_column = "curr.joined_members"
            order_by_asc = False
        elif RoomSortOrder(order_by) == RoomSortOrder.JOINED_LOCAL_MEMBERS:
            order_by_column = "curr.local_users_in_room"
            order_by_asc = False
        elif RoomSortOrder(order_by) == RoomSortOrder.VERSION:
            order_by_column = "rooms.room_version"
            order_by_asc = False
        elif RoomSortOrder(order_by) == RoomSortOrder.CREATOR:
            order_by_column = "rooms.creator"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.ENCRYPTION:
            order_by_column = "state.encryption"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.FEDERATABLE:
            order_by_column = "state.is_federatable"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.PUBLIC:
            order_by_column = "rooms.is_public"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.JOIN_RULES:
            order_by_column = "state.join_rules"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.GUEST_ACCESS:
            order_by_column = "state.guest_access"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.HISTORY_VISIBILITY:
            order_by_column = "state.history_visibility"
            order_by_asc = True
        elif RoomSortOrder(order_by) == RoomSortOrder.STATE_EVENTS:
            order_by_column = "curr.current_state_events"
            order_by_asc = False
        else:
            raise StoreError(
                500, "Incorrect value for order_by provided: %s" % order_by
            )

        # Whether to return the list in reverse order
        if reverse_order:
            # Flip the boolean
            order_by_asc = not order_by_asc

        # Create one query for getting the limited number of events that the user asked
        # for, and another query for getting the total number of events that could be
        # returned. Thus allowing us to see if there are more events to paginate through
        info_sql = """
            SELECT state.room_id, state.name, state.canonical_alias, curr.joined_members,
              curr.local_users_in_room, rooms.room_version, rooms.creator,
              state.encryption, state.is_federatable, rooms.is_public, state.join_rules,
              state.guest_access, state.history_visibility, curr.current_state_events,
              state.room_type
            FROM room_stats_state state
            INNER JOIN room_stats_current curr USING (room_id)
            INNER JOIN rooms USING (room_id)
            {where}
            ORDER BY {order_by} {direction}, state.room_id {direction}
            LIMIT ?
            OFFSET ?
        """.format(
            where=where_statement,
            order_by=order_by_column,
            direction="ASC" if order_by_asc else "DESC",
        )

        # Use a nested SELECT statement as SQL can't count(*) with an OFFSET
        count_sql = """
            SELECT count(*) FROM (
              SELECT room_id FROM room_stats_state state
              {where}
            ) AS get_room_ids
        """.format(
            where=where_statement,
        )

        def _get_rooms_paginate_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[Dict[str, Any]], int]:
            # Add the search term into the WHERE clause
            # and execute the data query
            txn.execute(info_sql, search_pattern + [limit, start])

            # Refactor room query data into a structured dictionary
            rooms = []
            for room in txn:
                rooms.append(
                    {
                        "room_id": room[0],
                        "name": room[1],
                        "canonical_alias": room[2],
                        "joined_members": room[3],
                        "joined_local_members": room[4],
                        "version": room[5],
                        "creator": room[6],
                        "encryption": room[7],
                        # room_stats_state.federatable is an integer on sqlite.
                        "federatable": bool(room[8]),
                        # rooms.is_public is an integer on sqlite.
                        "public": bool(room[9]),
                        "join_rules": room[10],
                        "guest_access": room[11],
                        "history_visibility": room[12],
                        "state_events": room[13],
                        "room_type": room[14],
                    }
                )

            # Execute the count query

            # Add the search term into the WHERE clause if present
            txn.execute(count_sql, search_pattern)

            room_count = cast(Tuple[int], txn.fetchone())
            return rooms, room_count[0]

        return await self.db_pool.runInteraction(
            "get_rooms_paginate",
            _get_rooms_paginate_txn,
        )

    @cached(max_entries=10000)
    async def get_ratelimit_for_user(self, user_id: str) -> Optional[RatelimitOverride]:
        """Check if there are any overrides for ratelimiting for the given user

        Args:
            user_id: user ID of the user
        Returns:
            RatelimitOverride if there is an override, else None. If the contents
            of RatelimitOverride are None or 0 then ratelimitng has been
            disabled for that user entirely.
        """
        row = await self.db_pool.simple_select_one(
            table="ratelimit_override",
            keyvalues={"user_id": user_id},
            retcols=("messages_per_second", "burst_count"),
            allow_none=True,
            desc="get_ratelimit_for_user",
        )

        if row:
            return RatelimitOverride(
                messages_per_second=row["messages_per_second"],
                burst_count=row["burst_count"],
            )
        else:
            return None

    async def set_ratelimit_for_user(
        self, user_id: str, messages_per_second: int, burst_count: int
    ) -> None:
        """Sets whether a user is set an overridden ratelimit.
        Args:
            user_id: user ID of the user
            messages_per_second: The number of actions that can be performed in a second.
            burst_count: How many actions that can be performed before being limited.
        """

        def set_ratelimit_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_upsert_txn(
                txn,
                table="ratelimit_override",
                keyvalues={"user_id": user_id},
                values={
                    "messages_per_second": messages_per_second,
                    "burst_count": burst_count,
                },
            )

            self._invalidate_cache_and_stream(
                txn, self.get_ratelimit_for_user, (user_id,)
            )

        await self.db_pool.runInteraction("set_ratelimit", set_ratelimit_txn)

    async def delete_ratelimit_for_user(self, user_id: str) -> None:
        """Delete an overridden ratelimit for a user.
        Args:
            user_id: user ID of the user
        """

        def delete_ratelimit_txn(txn: LoggingTransaction) -> None:
            row = self.db_pool.simple_select_one_txn(
                txn,
                table="ratelimit_override",
                keyvalues={"user_id": user_id},
                retcols=["user_id"],
                allow_none=True,
            )

            if not row:
                return

            # They are there, delete them.
            self.db_pool.simple_delete_one_txn(
                txn, "ratelimit_override", keyvalues={"user_id": user_id}
            )

            self._invalidate_cache_and_stream(
                txn, self.get_ratelimit_for_user, (user_id,)
            )

        await self.db_pool.runInteraction("delete_ratelimit", delete_ratelimit_txn)

    @cached()
    async def get_retention_policy_for_room(self, room_id: str) -> RetentionPolicy:
        """Get the retention policy for a given room.

        If no retention policy has been found for this room, returns a policy defined
        by the configured default policy (which has None as both the 'min_lifetime' and
        the 'max_lifetime' if no default policy has been defined in the server's
        configuration).

        If support for retention policies is disabled, a policy with a 'min_lifetime' and
        'max_lifetime' of None is returned.

        Args:
            room_id: The ID of the room to get the retention policy of.

        Returns:
            A dict containing "min_lifetime" and "max_lifetime" for this room.
        """
        # If the room retention feature is disabled, return a policy with no minimum nor
        # maximum. This prevents incorrectly filtering out events when sending to
        # the client.
        if not self.config.retention.retention_enabled:
            return RetentionPolicy()

        def get_retention_policy_for_room_txn(
            txn: LoggingTransaction,
        ) -> List[Dict[str, Optional[int]]]:
            txn.execute(
                """
                SELECT min_lifetime, max_lifetime FROM room_retention
                INNER JOIN current_state_events USING (event_id, room_id)
                WHERE room_id = ?;
                """,
                (room_id,),
            )

            return self.db_pool.cursor_to_dict(txn)

        ret = await self.db_pool.runInteraction(
            "get_retention_policy_for_room",
            get_retention_policy_for_room_txn,
        )

        # If we don't know this room ID, ret will be None, in this case return the default
        # policy.
        if not ret:
            return RetentionPolicy(
                min_lifetime=self.config.retention.retention_default_min_lifetime,
                max_lifetime=self.config.retention.retention_default_max_lifetime,
            )

        min_lifetime = ret[0]["min_lifetime"]
        max_lifetime = ret[0]["max_lifetime"]

        # If one of the room's policy's attributes isn't defined, use the matching
        # attribute from the default policy.
        # The default values will be None if no default policy has been defined, or if one
        # of the attributes is missing from the default policy.
        if min_lifetime is None:
            min_lifetime = self.config.retention.retention_default_min_lifetime

        if max_lifetime is None:
            max_lifetime = self.config.retention.retention_default_max_lifetime

        return RetentionPolicy(
            min_lifetime=min_lifetime,
            max_lifetime=max_lifetime,
        )

    async def get_media_mxcs_in_room(self, room_id: str) -> Tuple[List[str], List[str]]:
        """Retrieves all the local and remote media MXC URIs in a given room

        Args:
            room_id

        Returns:
            The local and remote media as a lists of the media IDs.
        """

        def _get_media_mxcs_in_room_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[str], List[str]]:
            local_mxcs, remote_mxcs = self._get_media_mxcs_in_room_txn(txn, room_id)
            local_media_mxcs = []
            remote_media_mxcs = []

            # Convert the IDs to MXC URIs
            for media_id in local_mxcs:
                local_media_mxcs.append("mxc://%s/%s" % (self.hs.hostname, media_id))
            for hostname, media_id in remote_mxcs:
                remote_media_mxcs.append("mxc://%s/%s" % (hostname, media_id))

            return local_media_mxcs, remote_media_mxcs

        return await self.db_pool.runInteraction(
            "get_media_ids_in_room", _get_media_mxcs_in_room_txn
        )

    async def quarantine_media_ids_in_room(
        self, room_id: str, quarantined_by: str
    ) -> int:
        """For a room loops through all events with media and quarantines
        the associated media
        """

        logger.info("Quarantining media in room: %s", room_id)

        def _quarantine_media_in_room_txn(txn: LoggingTransaction) -> int:
            local_mxcs, remote_mxcs = self._get_media_mxcs_in_room_txn(txn, room_id)
            return self._quarantine_media_txn(
                txn, local_mxcs, remote_mxcs, quarantined_by
            )

        return await self.db_pool.runInteraction(
            "quarantine_media_in_room", _quarantine_media_in_room_txn
        )

    def _get_media_mxcs_in_room_txn(
        self, txn: LoggingTransaction, room_id: str
    ) -> Tuple[List[str], List[Tuple[str, str]]]:
        """Retrieves all the local and remote media MXC URIs in a given room

        Returns:
            The local and remote media as a lists of tuples where the key is
            the hostname and the value is the media ID.
        """
        sql = """
            SELECT stream_ordering, json FROM events
            JOIN event_json USING (room_id, event_id)
            WHERE room_id = ?
                %(where_clause)s
                AND contains_url = ? AND outlier = ?
            ORDER BY stream_ordering DESC
            LIMIT ?
        """
        txn.execute(sql % {"where_clause": ""}, (room_id, True, False, 100))

        local_media_mxcs = []
        remote_media_mxcs = []

        while True:
            next_token = None
            for stream_ordering, content_json in txn:
                next_token = stream_ordering
                event_json = db_to_json(content_json)
                content = event_json["content"]
                content_url = content.get("url")
                thumbnail_url = content.get("info", {}).get("thumbnail_url")

                for url in (content_url, thumbnail_url):
                    if not url:
                        continue
                    matches = MXC_REGEX.match(url)
                    if matches:
                        hostname = matches.group(1)
                        media_id = matches.group(2)
                        if hostname == self.hs.hostname:
                            local_media_mxcs.append(media_id)
                        else:
                            remote_media_mxcs.append((hostname, media_id))

            if next_token is None:
                # We've gone through the whole room, so we're finished.
                break

            txn.execute(
                sql % {"where_clause": "AND stream_ordering < ?"},
                (room_id, next_token, True, False, 100),
            )

        return local_media_mxcs, remote_media_mxcs

    async def quarantine_media_by_id(
        self,
        server_name: str,
        media_id: str,
        quarantined_by: Optional[str],
    ) -> int:
        """quarantines or unquarantines a single local or remote media id

        Args:
            server_name: The name of the server that holds this media
            media_id: The ID of the media to be quarantined
            quarantined_by: The user ID that initiated the quarantine request
                If it is `None` media will be removed from quarantine
        """
        logger.info("Quarantining media: %s/%s", server_name, media_id)
        is_local = server_name == self.config.server.server_name

        def _quarantine_media_by_id_txn(txn: LoggingTransaction) -> int:
            local_mxcs = [media_id] if is_local else []
            remote_mxcs = [(server_name, media_id)] if not is_local else []

            return self._quarantine_media_txn(
                txn, local_mxcs, remote_mxcs, quarantined_by
            )

        return await self.db_pool.runInteraction(
            "quarantine_media_by_user", _quarantine_media_by_id_txn
        )

    async def quarantine_media_ids_by_user(
        self, user_id: str, quarantined_by: str
    ) -> int:
        """quarantines all local media associated with a single user

        Args:
            user_id: The ID of the user to quarantine media of
            quarantined_by: The ID of the user who made the quarantine request
        """

        def _quarantine_media_by_user_txn(txn: LoggingTransaction) -> int:
            local_media_ids = self._get_media_ids_by_user_txn(txn, user_id)
            return self._quarantine_media_txn(txn, local_media_ids, [], quarantined_by)

        return await self.db_pool.runInteraction(
            "quarantine_media_by_user", _quarantine_media_by_user_txn
        )

    def _get_media_ids_by_user_txn(
        self, txn: LoggingTransaction, user_id: str, filter_quarantined: bool = True
    ) -> List[str]:
        """Retrieves local media IDs by a given user

        Args:
            txn (cursor)
            user_id: The ID of the user to retrieve media IDs of

        Returns:
            The local and remote media as a lists of tuples where the key is
            the hostname and the value is the media ID.
        """
        # Local media
        sql = """
            SELECT media_id
            FROM local_media_repository
            WHERE user_id = ?
            """
        if filter_quarantined:
            sql += "AND quarantined_by IS NULL"
        txn.execute(sql, (user_id,))

        local_media_ids = [row[0] for row in txn]

        # TODO: Figure out all remote media a user has referenced in a message

        return local_media_ids

    def _quarantine_media_txn(
        self,
        txn: LoggingTransaction,
        local_mxcs: List[str],
        remote_mxcs: List[Tuple[str, str]],
        quarantined_by: Optional[str],
    ) -> int:
        """Quarantine and unquarantine local and remote media items

        Args:
            txn (cursor)
            local_mxcs: A list of local mxc URLs
            remote_mxcs: A list of (remote server, media id) tuples representing
                remote mxc URLs
            quarantined_by: The ID of the user who initiated the quarantine request
                If it is `None` media will be removed from quarantine
        Returns:
            The total number of media items quarantined
        """

        # Update all the tables to set the quarantined_by flag
        sql = """
            UPDATE local_media_repository
            SET quarantined_by = ?
            WHERE media_id = ?
        """

        # set quarantine
        if quarantined_by is not None:
            sql += "AND safe_from_quarantine = ?"
            txn.executemany(
                sql, [(quarantined_by, media_id, False) for media_id in local_mxcs]
            )
        # remove from quarantine
        else:
            txn.executemany(
                sql, [(quarantined_by, media_id) for media_id in local_mxcs]
            )

        # Note that a rowcount of -1 can be used to indicate no rows were affected.
        total_media_quarantined = txn.rowcount if txn.rowcount > 0 else 0

        txn.executemany(
            """
                UPDATE remote_media_cache
                SET quarantined_by = ?
                WHERE media_origin = ? AND media_id = ?
            """,
            ((quarantined_by, origin, media_id) for origin, media_id in remote_mxcs),
        )
        total_media_quarantined += txn.rowcount if txn.rowcount > 0 else 0

        return total_media_quarantined

    async def get_rooms_for_retention_period_in_range(
        self, min_ms: Optional[int], max_ms: Optional[int], include_null: bool = False
    ) -> Dict[str, RetentionPolicy]:
        """Retrieves all of the rooms within the given retention range.

        Optionally includes the rooms which don't have a retention policy.

        Args:
            min_ms: Duration in milliseconds that define the lower limit of
                the range to handle (exclusive). If None, doesn't set a lower limit.
            max_ms: Duration in milliseconds that define the upper limit of
                the range to handle (inclusive). If None, doesn't set an upper limit.
            include_null: Whether to include rooms which retention policy is NULL
                in the returned set.

        Returns:
            The rooms within this range, along with their retention
            policy. The key is "room_id", and maps to a dict describing the retention
            policy associated with this room ID. The keys for this nested dict are
            "min_lifetime" (int|None), and "max_lifetime" (int|None).
        """

        def get_rooms_for_retention_period_in_range_txn(
            txn: LoggingTransaction,
        ) -> Dict[str, RetentionPolicy]:
            range_conditions = []
            args = []

            if min_ms is not None:
                range_conditions.append("max_lifetime > ?")
                args.append(min_ms)

            if max_ms is not None:
                range_conditions.append("max_lifetime <= ?")
                args.append(max_ms)

            # Do a first query which will retrieve the rooms that have a retention policy
            # in their current state.
            sql = """
                SELECT room_id, min_lifetime, max_lifetime FROM room_retention
                INNER JOIN current_state_events USING (event_id, room_id)
                """

            if len(range_conditions):
                sql += " WHERE (" + " AND ".join(range_conditions) + ")"

                if include_null:
                    sql += " OR max_lifetime IS NULL"

            txn.execute(sql, args)

            rows = self.db_pool.cursor_to_dict(txn)
            rooms_dict = {}

            for row in rows:
                rooms_dict[row["room_id"]] = RetentionPolicy(
                    min_lifetime=row["min_lifetime"],
                    max_lifetime=row["max_lifetime"],
                )

            if include_null:
                # If required, do a second query that retrieves all of the rooms we know
                # of so we can handle rooms with no retention policy.
                sql = "SELECT DISTINCT room_id FROM current_state_events"

                txn.execute(sql)

                rows = self.db_pool.cursor_to_dict(txn)

                # If a room isn't already in the dict (i.e. it doesn't have a retention
                # policy in its state), add it with a null policy.
                for row in rows:
                    if row["room_id"] not in rooms_dict:
                        rooms_dict[row["room_id"]] = RetentionPolicy()

            return rooms_dict

        return await self.db_pool.runInteraction(
            "get_rooms_for_retention_period_in_range",
            get_rooms_for_retention_period_in_range_txn,
        )

    @cached(iterable=True)
    async def get_partial_state_servers_at_join(self, room_id: str) -> Sequence[str]:
        """Gets the list of servers in a partial state room at the time we joined it.

        Returns:
            The `servers_in_room` list from the `/send_join` response for partial state
            rooms. May not be accurate or complete, as it comes from a remote
            homeserver.
            An empty list for full state rooms.
        """
        return await self.db_pool.simple_select_onecol(
            "partial_state_rooms_servers",
            keyvalues={"room_id": room_id},
            retcol="server_name",
            desc="get_partial_state_servers_at_join",
        )

    async def get_partial_state_rooms_and_servers(
        self,
    ) -> Mapping[str, Collection[str]]:
        """Get all rooms containing events with partial state, and the servers known
        to be in the room.

        Returns:
            A dictionary of rooms with partial state, with room IDs as keys and
            lists of servers in rooms as values.
        """
        room_servers: Dict[str, List[str]] = {}

        rows = await self.db_pool.simple_select_list(
            "partial_state_rooms_servers",
            keyvalues=None,
            retcols=("room_id", "server_name"),
            desc="get_partial_state_rooms",
        )

        for row in rows:
            room_id = row["room_id"]
            server_name = row["server_name"]
            room_servers.setdefault(room_id, []).append(server_name)

        return room_servers

    async def clear_partial_state_room(self, room_id: str) -> bool:
        """Clears the partial state flag for a room.

        Args:
            room_id: The room whose partial state flag is to be cleared.

        Returns:
            `True` if the partial state flag has been cleared successfully.

            `False` if the partial state flag could not be cleared because the room
            still contains events with partial state.
        """
        try:
            await self.db_pool.runInteraction(
                "clear_partial_state_room", self._clear_partial_state_room_txn, room_id
            )
            return True
        except self.db_pool.engine.module.IntegrityError as e:
            # Assume that any `IntegrityError`s are due to partial state events.
            logger.info(
                "Exception while clearing lazy partial-state-room %s, retrying: %s",
                room_id,
                e,
            )
            return False

    def _clear_partial_state_room_txn(
        self, txn: LoggingTransaction, room_id: str
    ) -> None:
        DatabasePool.simple_delete_txn(
            txn,
            table="partial_state_rooms_servers",
            keyvalues={"room_id": room_id},
        )
        DatabasePool.simple_delete_one_txn(
            txn,
            table="partial_state_rooms",
            keyvalues={"room_id": room_id},
        )
        self._invalidate_cache_and_stream(txn, self.is_partial_state_room, (room_id,))
        self._invalidate_cache_and_stream(
            txn, self.get_partial_state_servers_at_join, (room_id,)
        )

        # We now delete anything from `device_lists_remote_pending` with a
        # stream ID less than the minimum
        # `partial_state_rooms.device_lists_stream_id`, as we no longer need them.
        device_lists_stream_id = DatabasePool.simple_select_one_onecol_txn(
            txn,
            table="partial_state_rooms",
            keyvalues={},
            retcol="MIN(device_lists_stream_id)",
            allow_none=True,
        )
        if device_lists_stream_id is None:
            # There are no rooms being currently partially joined, so we delete everything.
            txn.execute("DELETE FROM device_lists_remote_pending")
        else:
            sql = """
                DELETE FROM device_lists_remote_pending
                WHERE stream_id <= ?
            """
            txn.execute(sql, (device_lists_stream_id,))

    @cached()
    async def is_partial_state_room(self, room_id: str) -> bool:
        """Checks if this room has partial state.

        Returns true if this is a "partial-state" room, which means that the state
        at events in the room, and `current_state_events`, may not yet be
        complete.
        """

        entry = await self.db_pool.simple_select_one_onecol(
            table="partial_state_rooms",
            keyvalues={"room_id": room_id},
            retcol="room_id",
            allow_none=True,
            desc="is_partial_state_room",
        )

        return entry is not None

    async def get_join_event_id_and_device_lists_stream_id_for_partial_state(
        self, room_id: str
    ) -> Tuple[str, int]:
        """Get the event ID of the initial join that started the partial
        join, and the device list stream ID at the point we started the partial
        join.
        """

        result = await self.db_pool.simple_select_one(
            table="partial_state_rooms",
            keyvalues={"room_id": room_id},
            retcols=("join_event_id", "device_lists_stream_id"),
            desc="get_join_event_id_for_partial_state",
        )
        return result["join_event_id"], result["device_lists_stream_id"]


class _BackgroundUpdates:
    REMOVE_TOMESTONED_ROOMS_BG_UPDATE = "remove_tombstoned_rooms_from_directory"
    ADD_ROOMS_ROOM_VERSION_COLUMN = "add_rooms_room_version_column"
    POPULATE_ROOM_DEPTH_MIN_DEPTH2 = "populate_room_depth_min_depth2"
    REPLACE_ROOM_DEPTH_MIN_DEPTH = "replace_room_depth_min_depth"
    POPULATE_ROOMS_CREATOR_COLUMN = "populate_rooms_creator_column"
    ADD_ROOM_TYPE_COLUMN = "add_room_type_column"


_REPLACE_ROOM_DEPTH_SQL_COMMANDS = (
    "DROP TRIGGER populate_min_depth2_trigger ON room_depth",
    "DROP FUNCTION populate_min_depth2()",
    "ALTER TABLE room_depth DROP COLUMN min_depth",
    "ALTER TABLE room_depth RENAME COLUMN min_depth2 TO min_depth",
)


class RoomBackgroundUpdateStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            "insert_room_retention",
            self._background_insert_retention,
        )

        self.db_pool.updates.register_background_update_handler(
            _BackgroundUpdates.REMOVE_TOMESTONED_ROOMS_BG_UPDATE,
            self._remove_tombstoned_rooms_from_directory,
        )

        self.db_pool.updates.register_background_update_handler(
            _BackgroundUpdates.ADD_ROOMS_ROOM_VERSION_COLUMN,
            self._background_add_rooms_room_version_column,
        )

        self.db_pool.updates.register_background_update_handler(
            _BackgroundUpdates.ADD_ROOM_TYPE_COLUMN,
            self._background_add_room_type_column,
        )

        # BG updates to change the type of room_depth.min_depth
        self.db_pool.updates.register_background_update_handler(
            _BackgroundUpdates.POPULATE_ROOM_DEPTH_MIN_DEPTH2,
            self._background_populate_room_depth_min_depth2,
        )
        self.db_pool.updates.register_background_update_handler(
            _BackgroundUpdates.REPLACE_ROOM_DEPTH_MIN_DEPTH,
            self._background_replace_room_depth_min_depth,
        )

        self.db_pool.updates.register_background_update_handler(
            _BackgroundUpdates.POPULATE_ROOMS_CREATOR_COLUMN,
            self._background_populate_rooms_creator_column,
        )

    async def _background_insert_retention(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Retrieves a list of all rooms within a range and inserts an entry for each of
        them into the room_retention table.
        NULLs the property's columns if missing from the retention event in the room's
        state (or NULLs all of them if there's no retention event in the room's state),
        so that we fall back to the server's retention policy.
        """

        last_room = progress.get("room_id", "")

        def _background_insert_retention_txn(txn: LoggingTransaction) -> bool:
            txn.execute(
                """
                SELECT state.room_id, state.event_id, events.json
                FROM current_state_events as state
                LEFT JOIN event_json AS events ON (state.event_id = events.event_id)
                WHERE state.room_id > ? AND state.type = '%s'
                ORDER BY state.room_id ASC
                LIMIT ?;
                """
                % EventTypes.Retention,
                (last_room, batch_size),
            )

            rows = self.db_pool.cursor_to_dict(txn)

            if not rows:
                return True

            for row in rows:
                if not row["json"]:
                    retention_policy = {}
                else:
                    ev = db_to_json(row["json"])
                    retention_policy = ev["content"]

                self.db_pool.simple_insert_txn(
                    txn=txn,
                    table="room_retention",
                    values={
                        "room_id": row["room_id"],
                        "event_id": row["event_id"],
                        "min_lifetime": retention_policy.get("min_lifetime"),
                        "max_lifetime": retention_policy.get("max_lifetime"),
                    },
                )

            logger.info("Inserted %d rows into room_retention", len(rows))

            self.db_pool.updates._background_update_progress_txn(
                txn, "insert_room_retention", {"room_id": rows[-1]["room_id"]}
            )

            if batch_size > len(rows):
                return True
            else:
                return False

        end = await self.db_pool.runInteraction(
            "insert_room_retention",
            _background_insert_retention_txn,
        )

        if end:
            await self.db_pool.updates._end_background_update("insert_room_retention")

        return batch_size

    async def _background_add_rooms_room_version_column(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Background update to go and add room version information to `rooms`
        table from `current_state_events` table.
        """

        last_room_id = progress.get("room_id", "")

        def _background_add_rooms_room_version_column_txn(
            txn: LoggingTransaction,
        ) -> bool:
            sql = """
                SELECT room_id, json FROM current_state_events
                INNER JOIN event_json USING (room_id, event_id)
                WHERE room_id > ? AND type = 'm.room.create' AND state_key = ''
                ORDER BY room_id
                LIMIT ?
            """

            txn.execute(sql, (last_room_id, batch_size))

            updates = []
            for room_id, event_json in txn:
                event_dict = db_to_json(event_json)
                room_version_id = event_dict.get("content", {}).get(
                    "room_version", RoomVersions.V1.identifier
                )

                creator = event_dict.get("content").get("creator")

                updates.append((room_id, creator, room_version_id))

            if not updates:
                return True

            new_last_room_id = ""
            for room_id, creator, room_version_id in updates:
                # We upsert here just in case we don't already have a row,
                # mainly for paranoia as much badness would happen if we don't
                # insert the row and then try and get the room version for the
                # room.
                self.db_pool.simple_upsert_txn(
                    txn,
                    table="rooms",
                    keyvalues={"room_id": room_id},
                    values={"room_version": room_version_id},
                    insertion_values={"is_public": False, "creator": creator},
                )
                new_last_room_id = room_id

            self.db_pool.updates._background_update_progress_txn(
                txn,
                _BackgroundUpdates.ADD_ROOMS_ROOM_VERSION_COLUMN,
                {"room_id": new_last_room_id},
            )

            return False

        end = await self.db_pool.runInteraction(
            "_background_add_rooms_room_version_column",
            _background_add_rooms_room_version_column_txn,
        )

        if end:
            await self.db_pool.updates._end_background_update(
                _BackgroundUpdates.ADD_ROOMS_ROOM_VERSION_COLUMN
            )

        return batch_size

    async def _remove_tombstoned_rooms_from_directory(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Removes any rooms with tombstone events from the room directory

        Nowadays this is handled by the room upgrade handler, but we may have some
        that got left behind
        """

        last_room = progress.get("room_id", "")

        def _get_rooms(txn: LoggingTransaction) -> List[str]:
            txn.execute(
                """
                SELECT room_id
                FROM rooms r
                INNER JOIN current_state_events cse USING (room_id)
                WHERE room_id > ? AND r.is_public
                AND cse.type = '%s' AND cse.state_key = ''
                ORDER BY room_id ASC
                LIMIT ?;
                """
                % EventTypes.Tombstone,
                (last_room, batch_size),
            )

            return [row[0] for row in txn]

        rooms = await self.db_pool.runInteraction(
            "get_tombstoned_directory_rooms", _get_rooms
        )

        if not rooms:
            await self.db_pool.updates._end_background_update(
                _BackgroundUpdates.REMOVE_TOMESTONED_ROOMS_BG_UPDATE
            )
            return 0

        for room_id in rooms:
            logger.info("Removing tombstoned room %s from the directory", room_id)
            await self.set_room_is_public(room_id, False)

        await self.db_pool.updates._background_update_progress(
            _BackgroundUpdates.REMOVE_TOMESTONED_ROOMS_BG_UPDATE, {"room_id": rooms[-1]}
        )

        return len(rooms)

    @abstractmethod
    def set_room_is_public(self, room_id: str, is_public: bool) -> Awaitable[None]:
        # this will need to be implemented if a background update is performed with
        # existing (tombstoned, public) rooms in the database.
        #
        # It's overridden by RoomStore for the synapse master.
        raise NotImplementedError()

    async def has_auth_chain_index(self, room_id: str) -> bool:
        """Check if the room has (or can have) a chain cover index.

        Defaults to True if we don't have an entry in `rooms` table nor any
        events for the room.
        """

        has_auth_chain_index = await self.db_pool.simple_select_one_onecol(
            table="rooms",
            keyvalues={"room_id": room_id},
            retcol="has_auth_chain_index",
            desc="has_auth_chain_index",
            allow_none=True,
        )

        if has_auth_chain_index:
            return True

        # It's possible that we already have events for the room in our DB
        # without a corresponding room entry. If we do then we don't want to
        # mark the room as having an auth chain cover index.
        max_ordering = await self.db_pool.simple_select_one_onecol(
            table="events",
            keyvalues={"room_id": room_id},
            retcol="MAX(stream_ordering)",
            allow_none=True,
            desc="has_auth_chain_index_fallback",
        )

        return max_ordering is None

    async def _background_populate_room_depth_min_depth2(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Populate room_depth.min_depth2

        This is to deal with the fact that min_depth was initially created as a
        32-bit integer field.
        """

        def process(txn: LoggingTransaction) -> int:
            last_room = progress.get("last_room", "")
            txn.execute(
                """
                UPDATE room_depth SET min_depth2=min_depth
                WHERE room_id IN (
                   SELECT room_id FROM room_depth WHERE room_id > ?
                   ORDER BY room_id LIMIT ?
                )
                RETURNING room_id;
                """,
                (last_room, batch_size),
            )
            row_count = txn.rowcount
            if row_count == 0:
                return 0
            last_room = max(row[0] for row in txn)
            logger.info("populated room_depth up to %s", last_room)

            self.db_pool.updates._background_update_progress_txn(
                txn,
                _BackgroundUpdates.POPULATE_ROOM_DEPTH_MIN_DEPTH2,
                {"last_room": last_room},
            )
            return row_count

        result = await self.db_pool.runInteraction(
            "_background_populate_min_depth2", process
        )

        if result != 0:
            return result

        await self.db_pool.updates._end_background_update(
            _BackgroundUpdates.POPULATE_ROOM_DEPTH_MIN_DEPTH2
        )
        return 0

    async def _background_replace_room_depth_min_depth(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Drop the old 'min_depth' column and rename 'min_depth2' into its place."""

        def process(txn: Cursor) -> None:
            for sql in _REPLACE_ROOM_DEPTH_SQL_COMMANDS:
                logger.info("completing room_depth migration: %s", sql)
                txn.execute(sql)

        await self.db_pool.runInteraction("_background_replace_room_depth", process)

        await self.db_pool.updates._end_background_update(
            _BackgroundUpdates.REPLACE_ROOM_DEPTH_MIN_DEPTH,
        )

        return 0

    async def _background_populate_rooms_creator_column(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Background update to go and add creator information to `rooms`
        table from `current_state_events` table.
        """

        last_room_id = progress.get("room_id", "")

        def _background_populate_rooms_creator_column_txn(
            txn: LoggingTransaction,
        ) -> bool:
            sql = """
                SELECT room_id, json FROM event_json
                INNER JOIN rooms AS room USING (room_id)
                INNER JOIN current_state_events AS state_event USING (room_id, event_id)
                WHERE room_id > ? AND (room.creator IS NULL OR room.creator = '') AND state_event.type = 'm.room.create' AND state_event.state_key = ''
                ORDER BY room_id
                LIMIT ?
            """

            txn.execute(sql, (last_room_id, batch_size))
            room_id_to_create_event_results = txn.fetchall()

            new_last_room_id = ""
            for room_id, event_json in room_id_to_create_event_results:
                event_dict = db_to_json(event_json)

                creator = event_dict.get("content").get(EventContentFields.ROOM_CREATOR)

                self.db_pool.simple_update_txn(
                    txn,
                    table="rooms",
                    keyvalues={"room_id": room_id},
                    updatevalues={"creator": creator},
                )
                new_last_room_id = room_id

            if new_last_room_id == "":
                return True

            self.db_pool.updates._background_update_progress_txn(
                txn,
                _BackgroundUpdates.POPULATE_ROOMS_CREATOR_COLUMN,
                {"room_id": new_last_room_id},
            )

            return False

        end = await self.db_pool.runInteraction(
            "_background_populate_rooms_creator_column",
            _background_populate_rooms_creator_column_txn,
        )

        if end:
            await self.db_pool.updates._end_background_update(
                _BackgroundUpdates.POPULATE_ROOMS_CREATOR_COLUMN
            )

        return batch_size

    async def _background_add_room_type_column(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Background update to go and add room_type information to `room_stats_state`
        table from `event_json` table.
        """

        last_room_id = progress.get("room_id", "")

        def _background_add_room_type_column_txn(
            txn: LoggingTransaction,
        ) -> bool:
            sql = """
                SELECT state.room_id, json FROM event_json
                INNER JOIN current_state_events AS state USING (event_id)
                WHERE state.room_id > ? AND type = 'm.room.create'
                ORDER BY state.room_id
                LIMIT ?
            """

            txn.execute(sql, (last_room_id, batch_size))
            room_id_to_create_event_results = txn.fetchall()

            new_last_room_id = None
            for room_id, event_json in room_id_to_create_event_results:
                event_dict = db_to_json(event_json)

                room_type = event_dict.get("content", {}).get(
                    EventContentFields.ROOM_TYPE, None
                )
                if isinstance(room_type, str):
                    self.db_pool.simple_update_txn(
                        txn,
                        table="room_stats_state",
                        keyvalues={"room_id": room_id},
                        updatevalues={"room_type": room_type},
                    )

                new_last_room_id = room_id

            if new_last_room_id is None:
                return True

            self.db_pool.updates._background_update_progress_txn(
                txn,
                _BackgroundUpdates.ADD_ROOM_TYPE_COLUMN,
                {"room_id": new_last_room_id},
            )

            return False

        end = await self.db_pool.runInteraction(
            "_background_add_room_type_column",
            _background_add_room_type_column_txn,
        )

        if end:
            await self.db_pool.updates._end_background_update(
                _BackgroundUpdates.ADD_ROOM_TYPE_COLUMN
            )

        return batch_size


class RoomStore(RoomBackgroundUpdateStore, RoomWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._event_reports_id_gen = IdGenerator(db_conn, "event_reports", "id")

    async def upsert_room_on_join(
        self, room_id: str, room_version: RoomVersion, state_events: List[EventBase]
    ) -> None:
        """Ensure that the room is stored in the table

        Called when we join a room over federation, and overwrites any room version
        currently in the table.
        """
        # It's possible that we already have events for the room in our DB
        # without a corresponding room entry. If we do then we don't want to
        # mark the room as having an auth chain cover index.
        has_auth_chain_index = await self.has_auth_chain_index(room_id)

        create_event = None
        for e in state_events:
            if (e.type, e.state_key) == (EventTypes.Create, ""):
                create_event = e
                break

        if create_event is None:
            # If the state doesn't have a create event then the room is
            # invalid, and it would fail auth checks anyway.
            raise StoreError(400, "No create event in state")

        room_creator = create_event.content.get(EventContentFields.ROOM_CREATOR)

        if not isinstance(room_creator, str):
            # If the create event does not have a creator then the room is
            # invalid, and it would fail auth checks anyway.
            raise StoreError(400, "No creator defined on the create event")

        await self.db_pool.simple_upsert(
            desc="upsert_room_on_join",
            table="rooms",
            keyvalues={"room_id": room_id},
            values={"room_version": room_version.identifier},
            insertion_values={
                "is_public": False,
                "creator": room_creator,
                "has_auth_chain_index": has_auth_chain_index,
            },
            # rooms has a unique constraint on room_id, so no need to lock when doing an
            # emulated upsert.
            lock=False,
        )

    async def store_partial_state_room(
        self,
        room_id: str,
        servers: Collection[str],
        device_lists_stream_id: int,
    ) -> None:
        """Mark the given room as containing events with partial state.

        We also store additional data that describes _when_ we first partial-joined this
        room, which helps us to keep other homeservers in sync when we finally fully
        join this room.

        We do not include a `join_event_id` here---we need to wait for the join event
        to be persisted first.

        Args:
            room_id: the ID of the room
            servers: other servers known to be in the room
            device_lists_stream_id: the device_lists stream ID at the time when we first
                joined the room.
        """
        await self.db_pool.runInteraction(
            "store_partial_state_room",
            self._store_partial_state_room_txn,
            room_id,
            servers,
            device_lists_stream_id,
        )

    def _store_partial_state_room_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        servers: Collection[str],
        device_lists_stream_id: int,
    ) -> None:
        DatabasePool.simple_insert_txn(
            txn,
            table="partial_state_rooms",
            values={
                "room_id": room_id,
                "device_lists_stream_id": device_lists_stream_id,
                # To be updated later once the join event is persisted.
                "join_event_id": None,
            },
        )
        DatabasePool.simple_insert_many_txn(
            txn,
            table="partial_state_rooms_servers",
            keys=("room_id", "server_name"),
            values=((room_id, s) for s in servers),
        )
        self._invalidate_cache_and_stream(txn, self.is_partial_state_room, (room_id,))
        self._invalidate_cache_and_stream(
            txn, self.get_partial_state_servers_at_join, (room_id,)
        )

    async def write_partial_state_rooms_join_event_id(
        self,
        room_id: str,
        join_event_id: str,
    ) -> None:
        """Record the join event which resulted from a partial join.

        We do this separately to `store_partial_state_room` because we need to wait for
        the join event to be persisted. Otherwise we violate a foreign key constraint.
        """
        await self.db_pool.runInteraction(
            "write_partial_state_rooms_join_event_id",
            self._write_partial_state_rooms_join_event_id,
            room_id,
            join_event_id,
        )

    def _write_partial_state_rooms_join_event_id(
        self,
        txn: LoggingTransaction,
        room_id: str,
        join_event_id: str,
    ) -> None:
        DatabasePool.simple_update_txn(
            txn,
            table="partial_state_rooms",
            keyvalues={"room_id": room_id},
            updatevalues={"join_event_id": join_event_id},
        )

    async def maybe_store_room_on_outlier_membership(
        self, room_id: str, room_version: RoomVersion
    ) -> None:
        """
        When we receive an invite or any other event over federation that may relate to a room
        we are not in, store the version of the room if we don't already know the room version.
        """
        # It's possible that we already have events for the room in our DB
        # without a corresponding room entry. If we do then we don't want to
        # mark the room as having an auth chain cover index.
        has_auth_chain_index = await self.has_auth_chain_index(room_id)

        await self.db_pool.simple_upsert(
            desc="maybe_store_room_on_outlier_membership",
            table="rooms",
            keyvalues={"room_id": room_id},
            values={},
            insertion_values={
                "room_version": room_version.identifier,
                "is_public": False,
                # We don't worry about setting the `creator` here because
                # we don't process any messages in a room while a user is
                # invited (only after the join).
                "creator": "",
                "has_auth_chain_index": has_auth_chain_index,
            },
            # rooms has a unique constraint on room_id, so no need to lock when doing an
            # emulated upsert.
            lock=False,
        )

    async def set_room_is_public(self, room_id: str, is_public: bool) -> None:
        await self.db_pool.simple_update_one(
            table="rooms",
            keyvalues={"room_id": room_id},
            updatevalues={"is_public": is_public},
            desc="set_room_is_public",
        )

        self.hs.get_notifier().on_new_replication_data()

    async def set_room_is_public_appservice(
        self, room_id: str, appservice_id: str, network_id: str, is_public: bool
    ) -> None:
        """Edit the appservice/network specific public room list.

        Each appservice can have a number of published room lists associated
        with them, keyed off of an appservice defined `network_id`, which
        basically represents a single instance of a bridge to a third party
        network.

        Args:
            room_id
            appservice_id
            network_id
            is_public: Whether to publish or unpublish the room from the list.
        """

        if is_public:
            await self.db_pool.simple_upsert(
                table="appservice_room_list",
                keyvalues={
                    "appservice_id": appservice_id,
                    "network_id": network_id,
                    "room_id": room_id,
                },
                values={},
                insertion_values={
                    "appservice_id": appservice_id,
                    "network_id": network_id,
                    "room_id": room_id,
                },
                desc="set_room_is_public_appservice_true",
            )
        else:
            await self.db_pool.simple_delete(
                table="appservice_room_list",
                keyvalues={
                    "appservice_id": appservice_id,
                    "network_id": network_id,
                    "room_id": room_id,
                },
                desc="set_room_is_public_appservice_false",
            )

        self.hs.get_notifier().on_new_replication_data()

    async def add_event_report(
        self,
        room_id: str,
        event_id: str,
        user_id: str,
        reason: Optional[str],
        content: JsonDict,
        received_ts: int,
    ) -> None:
        next_id = self._event_reports_id_gen.get_next()
        await self.db_pool.simple_insert(
            table="event_reports",
            values={
                "id": next_id,
                "received_ts": received_ts,
                "room_id": room_id,
                "event_id": event_id,
                "user_id": user_id,
                "reason": reason,
                "content": json_encoder.encode(content),
            },
            desc="add_event_report",
        )

    async def get_event_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve an event report

        Args:
            report_id: ID of reported event in database
        Returns:
            event_report: json list of information from event report
        """

        def _get_event_report_txn(
            txn: LoggingTransaction, report_id: int
        ) -> Optional[Dict[str, Any]]:

            sql = """
                SELECT
                    er.id,
                    er.received_ts,
                    er.room_id,
                    er.event_id,
                    er.user_id,
                    er.content,
                    events.sender,
                    room_stats_state.canonical_alias,
                    room_stats_state.name,
                    event_json.json AS event_json
                FROM event_reports AS er
                LEFT JOIN events
                    ON events.event_id = er.event_id
                JOIN event_json
                    ON event_json.event_id = er.event_id
                JOIN room_stats_state
                    ON room_stats_state.room_id = er.room_id
                WHERE er.id = ?
            """

            txn.execute(sql, [report_id])
            row = txn.fetchone()

            if not row:
                return None

            event_report = {
                "id": row[0],
                "received_ts": row[1],
                "room_id": row[2],
                "event_id": row[3],
                "user_id": row[4],
                "score": db_to_json(row[5]).get("score"),
                "reason": db_to_json(row[5]).get("reason"),
                "sender": row[6],
                "canonical_alias": row[7],
                "name": row[8],
                "event_json": db_to_json(row[9]),
            }

            return event_report

        return await self.db_pool.runInteraction(
            "get_event_report", _get_event_report_txn, report_id
        )

    async def get_event_reports_paginate(
        self,
        start: int,
        limit: int,
        direction: str = "b",
        user_id: Optional[str] = None,
        room_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve a paginated list of event reports

        Args:
            start: event offset to begin the query from
            limit: number of rows to retrieve
            direction: Whether to fetch the most recent first (`"b"`) or the
                oldest first (`"f"`)
            user_id: search for user_id. Ignored if user_id is None
            room_id: search for room_id. Ignored if room_id is None
        Returns:
            event_reports: json list of event reports
            count: total number of event reports matching the filter criteria
        """

        def _get_event_reports_paginate_txn(
            txn: LoggingTransaction,
        ) -> Tuple[List[Dict[str, Any]], int]:
            filters = []
            args: List[object] = []

            if user_id:
                filters.append("er.user_id LIKE ?")
                args.extend(["%" + user_id + "%"])
            if room_id:
                filters.append("er.room_id LIKE ?")
                args.extend(["%" + room_id + "%"])

            if direction == "b":
                order = "DESC"
            else:
                order = "ASC"

            where_clause = "WHERE " + " AND ".join(filters) if len(filters) > 0 else ""

            # We join on room_stats_state despite not using any columns from it
            # because the join can influence the number of rows returned;
            # e.g. a room that doesn't have state, maybe because it was deleted.
            # The query returning the total count should be consistent with
            # the query returning the results.
            sql = """
                SELECT COUNT(*) as total_event_reports
                FROM event_reports AS er
                JOIN room_stats_state ON room_stats_state.room_id = er.room_id
                {}
                """.format(
                where_clause
            )
            txn.execute(sql, args)
            count = cast(Tuple[int], txn.fetchone())[0]

            sql = """
                SELECT
                    er.id,
                    er.received_ts,
                    er.room_id,
                    er.event_id,
                    er.user_id,
                    er.content,
                    events.sender,
                    room_stats_state.canonical_alias,
                    room_stats_state.name
                FROM event_reports AS er
                LEFT JOIN events
                    ON events.event_id = er.event_id
                JOIN room_stats_state
                    ON room_stats_state.room_id = er.room_id
                {where_clause}
                ORDER BY er.received_ts {order}
                LIMIT ?
                OFFSET ?
            """.format(
                where_clause=where_clause,
                order=order,
            )

            args += [limit, start]
            txn.execute(sql, args)

            event_reports = []
            for row in txn:
                try:
                    s = db_to_json(row[5]).get("score")
                    r = db_to_json(row[5]).get("reason")
                except Exception:
                    logger.error("Unable to parse json from event_reports: %s", row[0])
                    continue
                event_reports.append(
                    {
                        "id": row[0],
                        "received_ts": row[1],
                        "room_id": row[2],
                        "event_id": row[3],
                        "user_id": row[4],
                        "score": s,
                        "reason": r,
                        "sender": row[6],
                        "canonical_alias": row[7],
                        "name": row[8],
                    }
                )

            return event_reports, count

        return await self.db_pool.runInteraction(
            "get_event_reports_paginate", _get_event_reports_paginate_txn
        )

    async def block_room(self, room_id: str, user_id: str) -> None:
        """Marks the room as blocked.

        Can be called multiple times (though we'll only track the last user to
        block this room).

        Can be called on a room unknown to this homeserver.

        Args:
            room_id: Room to block
            user_id: Who blocked it
        """
        await self.db_pool.simple_upsert(
            table="blocked_rooms",
            keyvalues={"room_id": room_id},
            values={},
            insertion_values={"user_id": user_id},
            desc="block_room",
        )
        await self.db_pool.runInteraction(
            "block_room_invalidation",
            self._invalidate_cache_and_stream,
            self.is_room_blocked,
            (room_id,),
        )

    async def unblock_room(self, room_id: str) -> None:
        """Remove the room from blocking list.

        Args:
            room_id: Room to unblock
        """
        await self.db_pool.simple_delete(
            table="blocked_rooms",
            keyvalues={"room_id": room_id},
            desc="unblock_room",
        )
        await self.db_pool.runInteraction(
            "block_room_invalidation",
            self._invalidate_cache_and_stream,
            self.is_room_blocked,
            (room_id,),
        )

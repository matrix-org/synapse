# Copyright 2017 Vector Creations Ltd
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
import re
from typing import (
    TYPE_CHECKING,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    cast,
)

from typing_extensions import TypedDict

from synapse.api.errors import StoreError
from synapse.util.stringutils import non_null_str_or_none

if TYPE_CHECKING:
    from synapse.server import HomeServer

from synapse.api.constants import EventTypes, HistoryVisibility, JoinRules
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.state import StateFilter
from synapse.storage.databases.main.state_deltas import StateDeltasStore
from synapse.storage.engines import PostgresEngine, Sqlite3Engine
from synapse.types import (
    JsonDict,
    UserProfile,
    get_domain_from_id,
    get_localpart_from_id,
)
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)

TEMP_TABLE = "_temp_populate_user_directory"


class UserDirectoryBackgroundUpdateStore(StateDeltasStore):
    # How many records do we calculate before sending it to
    # add_users_who_share_private_rooms?
    SHARE_PRIVATE_WORKING_SET = 500

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ) -> None:
        super().__init__(database, db_conn, hs)

        self.server_name: str = hs.hostname

        self.db_pool.updates.register_background_update_handler(
            "populate_user_directory_createtables",
            self._populate_user_directory_createtables,
        )
        self.db_pool.updates.register_background_update_handler(
            "populate_user_directory_process_rooms",
            self._populate_user_directory_process_rooms,
        )
        self.db_pool.updates.register_background_update_handler(
            "populate_user_directory_process_users",
            self._populate_user_directory_process_users,
        )
        self.db_pool.updates.register_background_update_handler(
            "populate_user_directory_cleanup", self._populate_user_directory_cleanup
        )

    async def _populate_user_directory_createtables(
        self, progress: JsonDict, batch_size: int
    ) -> int:

        # Get all the rooms that we want to process.
        def _make_staging_area(txn: LoggingTransaction) -> None:
            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_rooms(room_id TEXT NOT NULL, events BIGINT NOT NULL)"
            )
            txn.execute(sql)

            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_position(position TEXT NOT NULL)"
            )
            txn.execute(sql)

            # Get rooms we want to process from the database
            sql = """
                SELECT room_id, count(*) FROM current_state_events
                GROUP BY room_id
            """
            txn.execute(sql)
            rooms = list(txn.fetchall())
            self.db_pool.simple_insert_many_txn(
                txn, TEMP_TABLE + "_rooms", keys=("room_id", "events"), values=rooms
            )
            del rooms

            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_users(user_id TEXT NOT NULL)"
            )
            txn.execute(sql)

            txn.execute("SELECT name FROM users")
            users = list(txn.fetchall())

            self.db_pool.simple_insert_many_txn(
                txn, TEMP_TABLE + "_users", keys=("user_id",), values=users
            )

        new_pos = await self.get_max_stream_id_in_current_state_deltas()
        await self.db_pool.runInteraction(
            "populate_user_directory_temp_build", _make_staging_area
        )
        await self.db_pool.simple_insert(
            TEMP_TABLE + "_position", {"position": new_pos}
        )

        await self.db_pool.updates._end_background_update(
            "populate_user_directory_createtables"
        )
        return 1

    async def _populate_user_directory_cleanup(
        self,
        progress: JsonDict,
        batch_size: int,
    ) -> int:
        """
        Update the user directory stream position, then clean up the old tables.
        """
        position = await self.db_pool.simple_select_one_onecol(
            TEMP_TABLE + "_position", {}, "position"
        )
        await self.update_user_directory_stream_pos(position)

        def _delete_staging_area(txn: LoggingTransaction) -> None:
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_rooms")
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_users")
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_position")

        await self.db_pool.runInteraction(
            "populate_user_directory_cleanup", _delete_staging_area
        )

        await self.db_pool.updates._end_background_update(
            "populate_user_directory_cleanup"
        )
        return 1

    async def _populate_user_directory_process_rooms(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """
        Rescan the state of all rooms so we can track

        - who's in a public room;
        - which local users share a private room with other users (local
          and remote); and
        - who should be in the user_directory.

        Args:
            progress (dict)
            batch_size (int): Maximum number of state events to process
                per cycle.

        Returns:
            number of events processed.
        """
        # If we don't have progress filed, delete everything.
        if not progress:
            await self.delete_all_from_user_dir()

        def _get_next_batch(
            txn: LoggingTransaction,
        ) -> Optional[Sequence[Tuple[str, int]]]:
            # Only fetch 250 rooms, so we don't fetch too many at once, even
            # if those 250 rooms have less than batch_size state events.
            sql = """
                SELECT room_id, events FROM %s
                ORDER BY events DESC
                LIMIT 250
            """ % (
                TEMP_TABLE + "_rooms",
            )
            txn.execute(sql)
            rooms_to_work_on = cast(List[Tuple[str, int]], txn.fetchall())

            if not rooms_to_work_on:
                return None

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            txn.execute("SELECT COUNT(*) FROM " + TEMP_TABLE + "_rooms")
            result = txn.fetchone()
            assert result is not None
            progress["remaining"] = result[0]

            return rooms_to_work_on

        rooms_to_work_on = await self.db_pool.runInteraction(
            "populate_user_directory_temp_read", _get_next_batch
        )

        # No more rooms -- complete the transaction.
        if not rooms_to_work_on:
            await self.db_pool.updates._end_background_update(
                "populate_user_directory_process_rooms"
            )
            return 1

        logger.debug(
            "Processing the next %d rooms of %d remaining"
            % (len(rooms_to_work_on), progress["remaining"])
        )

        processed_event_count = 0

        for room_id, event_count in rooms_to_work_on:
            is_in_room = await self.is_host_joined(room_id, self.server_name)  # type: ignore[attr-defined]

            if is_in_room:
                users_with_profile = await self.get_users_in_room_with_profiles(room_id)  # type: ignore[attr-defined]
                # Throw away users excluded from the directory.
                users_with_profile = {
                    user_id: profile
                    for user_id, profile in users_with_profile.items()
                    if not self.hs.is_mine_id(user_id)
                    or await self.should_include_local_user_in_dir(user_id)
                }

                # Upsert a user_directory record for each remote user we see.
                for user_id, profile in users_with_profile.items():
                    # Local users are processed separately in
                    # `_populate_user_directory_users`; there we can read from
                    # the `profiles` table to ensure we don't leak their per-room
                    # profiles. It also means we write local users to this table
                    # exactly once, rather than once for every room they're in.
                    if self.hs.is_mine_id(user_id):
                        continue
                    # TODO `users_with_profile` above reads from the `user_directory`
                    #   table, meaning that `profile` is bespoke to this room.
                    #   and this leaks remote users' per-room profiles to the user directory.
                    await self.update_profile_in_user_dir(
                        user_id, profile.display_name, profile.avatar_url
                    )

                # Now update the room sharing tables to include this room.
                is_public = await self.is_room_world_readable_or_publicly_joinable(
                    room_id
                )
                if is_public:
                    if users_with_profile:
                        await self.add_users_in_public_rooms(
                            room_id, users_with_profile.keys()
                        )
                else:
                    to_insert = set()
                    for user_id in users_with_profile:
                        # We want the set of pairs (L, M) where L and M are
                        # in `users_with_profile` and L is local.
                        # Do so by looking for the local user L first.
                        if not self.hs.is_mine_id(user_id):
                            continue

                        for other_user_id in users_with_profile:
                            if user_id == other_user_id:
                                continue

                            user_set = (user_id, other_user_id)
                            to_insert.add(user_set)

                            # If it gets too big, stop and write to the database
                            # to prevent storing too much in RAM.
                            if len(to_insert) >= self.SHARE_PRIVATE_WORKING_SET:
                                await self.add_users_who_share_private_room(
                                    room_id, to_insert
                                )
                                to_insert.clear()

                    if to_insert:
                        await self.add_users_who_share_private_room(room_id, to_insert)
                        to_insert.clear()

            # We've finished a room. Delete it from the table.
            await self.db_pool.simple_delete_one(
                TEMP_TABLE + "_rooms", {"room_id": room_id}
            )
            # Update the remaining counter.
            progress["remaining"] -= 1
            await self.db_pool.runInteraction(
                "populate_user_directory",
                self.db_pool.updates._background_update_progress_txn,
                "populate_user_directory_process_rooms",
                progress,
            )

            processed_event_count += event_count

            if processed_event_count > batch_size:
                # Don't process any more rooms, we've hit our batch size.
                return processed_event_count

        return processed_event_count

    async def _populate_user_directory_process_users(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """
        Add all local users to the user directory.
        """

        def _get_next_batch(txn: LoggingTransaction) -> Optional[List[str]]:
            sql = "SELECT user_id FROM %s LIMIT %s" % (
                TEMP_TABLE + "_users",
                str(batch_size),
            )
            txn.execute(sql)
            user_result = cast(List[Tuple[str]], txn.fetchall())

            if not user_result:
                return None

            users_to_work_on = [x[0] for x in user_result]

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            sql = "SELECT COUNT(*) FROM " + TEMP_TABLE + "_users"
            txn.execute(sql)
            count_result = txn.fetchone()
            assert count_result is not None
            progress["remaining"] = count_result[0]

            return users_to_work_on

        users_to_work_on = await self.db_pool.runInteraction(
            "populate_user_directory_temp_read", _get_next_batch
        )

        # No more users -- complete the transaction.
        if not users_to_work_on:
            await self.db_pool.updates._end_background_update(
                "populate_user_directory_process_users"
            )
            return 1

        logger.debug(
            "Processing the next %d users of %d remaining"
            % (len(users_to_work_on), progress["remaining"])
        )

        for user_id in users_to_work_on:
            if await self.should_include_local_user_in_dir(user_id):
                profile = await self.get_profileinfo(get_localpart_from_id(user_id))  # type: ignore[attr-defined]
                await self.update_profile_in_user_dir(
                    user_id, profile.display_name, profile.avatar_url
                )

            # We've finished processing a user. Delete it from the table.
            await self.db_pool.simple_delete_one(
                TEMP_TABLE + "_users", {"user_id": user_id}
            )
            # Update the remaining counter.
            progress["remaining"] -= 1
            await self.db_pool.runInteraction(
                "populate_user_directory",
                self.db_pool.updates._background_update_progress_txn,
                "populate_user_directory_process_users",
                progress,
            )

        return len(users_to_work_on)

    async def should_include_local_user_in_dir(self, user: str) -> bool:
        """Certain classes of local user are omitted from the user directory.
        Is this user one of them?
        """
        # We're opting to exclude the appservice sender (user defined by the
        # `sender_localpart` in the appservice registration) even though
        # technically it could be DM-able. In the future, this could potentially
        # be configurable per-appservice whether the appservice sender can be
        # contacted.
        if self.get_app_service_by_user_id(user) is not None:  # type: ignore[attr-defined]
            return False

        # We're opting to exclude appservice users (anyone matching the user
        # namespace regex in the appservice registration) even though technically
        # they could be DM-able. In the future, this could potentially
        # be configurable per-appservice whether the appservice users can be
        # contacted.
        if self.get_if_app_services_interested_in_user(user):  # type: ignore[attr-defined]
            # TODO we might want to make this configurable for each app service
            return False

        # Support users are for diagnostics and should not appear in the user directory.
        if await self.is_support_user(user):  # type: ignore[attr-defined]
            return False

        # Deactivated users aren't contactable, so should not appear in the user directory.
        try:
            if await self.get_user_deactivated_status(user):  # type: ignore[attr-defined]
                return False
        except StoreError:
            # No such user in the users table. No need to do this when calling
            # is_support_user---that returns False if the user is missing.
            return False

        return True

    async def is_room_world_readable_or_publicly_joinable(self, room_id: str) -> bool:
        """Check if the room is either world_readable or publically joinable"""

        # Create a state filter that only queries join and history state event
        types_to_filter = (
            (EventTypes.JoinRules, ""),
            (EventTypes.RoomHistoryVisibility, ""),
        )

        # Getting the partial state is fine, as we're not looking at membership
        # events.
        current_state_ids = await self.get_partial_filtered_current_state_ids(  # type: ignore[attr-defined]
            room_id, StateFilter.from_types(types_to_filter)
        )

        join_rules_id = current_state_ids.get((EventTypes.JoinRules, ""))
        if join_rules_id:
            join_rule_ev = await self.get_event(join_rules_id, allow_none=True)  # type: ignore[attr-defined]
            if join_rule_ev:
                if join_rule_ev.content.get("join_rule") == JoinRules.PUBLIC:
                    return True

        hist_vis_id = current_state_ids.get((EventTypes.RoomHistoryVisibility, ""))
        if hist_vis_id:
            hist_vis_ev = await self.get_event(hist_vis_id, allow_none=True)  # type: ignore[attr-defined]
            if hist_vis_ev:
                if (
                    hist_vis_ev.content.get("history_visibility")
                    == HistoryVisibility.WORLD_READABLE
                ):
                    return True

        return False

    async def update_profile_in_user_dir(
        self, user_id: str, display_name: Optional[str], avatar_url: Optional[str]
    ) -> None:
        """
        Update or add a user's profile in the user directory.
        """
        # If the display name or avatar URL are unexpected types, replace with None.
        display_name = non_null_str_or_none(display_name)
        avatar_url = non_null_str_or_none(avatar_url)

        def _update_profile_in_user_dir_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_upsert_txn(
                txn,
                table="user_directory",
                keyvalues={"user_id": user_id},
                values={"display_name": display_name, "avatar_url": avatar_url},
                lock=False,  # We're only inserter
            )

            if isinstance(self.database_engine, PostgresEngine):
                # We weight the localpart most highly, then display name and finally
                # server name
                sql = """
                        INSERT INTO user_directory_search(user_id, vector)
                        VALUES (?,
                            setweight(to_tsvector('simple', ?), 'A')
                            || setweight(to_tsvector('simple', ?), 'D')
                            || setweight(to_tsvector('simple', COALESCE(?, '')), 'B')
                        ) ON CONFLICT (user_id) DO UPDATE SET vector=EXCLUDED.vector
                    """
                txn.execute(
                    sql,
                    (
                        user_id,
                        get_localpart_from_id(user_id),
                        get_domain_from_id(user_id),
                        display_name,
                    ),
                )
            elif isinstance(self.database_engine, Sqlite3Engine):
                value = "%s %s" % (user_id, display_name) if display_name else user_id
                self.db_pool.simple_upsert_txn(
                    txn,
                    table="user_directory_search",
                    keyvalues={"user_id": user_id},
                    values={"value": value},
                    lock=False,  # We're only inserter
                )
            else:
                # This should be unreachable.
                raise Exception("Unrecognized database engine")

            txn.call_after(self.get_user_in_directory.invalidate, (user_id,))

        await self.db_pool.runInteraction(
            "update_profile_in_user_dir", _update_profile_in_user_dir_txn
        )

    async def add_users_who_share_private_room(
        self, room_id: str, user_id_tuples: Iterable[Tuple[str, str]]
    ) -> None:
        """Insert entries into the users_who_share_private_rooms table. The first
        user should be a local user.

        Args:
            room_id
            user_id_tuples: iterable of 2-tuple of user IDs.
        """

        await self.db_pool.simple_upsert_many(
            table="users_who_share_private_rooms",
            key_names=["user_id", "other_user_id", "room_id"],
            key_values=[
                (user_id, other_user_id, room_id)
                for user_id, other_user_id in user_id_tuples
            ],
            value_names=(),
            value_values=(),
            desc="add_users_who_share_room",
        )

    async def add_users_in_public_rooms(
        self, room_id: str, user_ids: Iterable[str]
    ) -> None:
        """Insert entries into the users_in_public_rooms table.

        Args:
            room_id
            user_ids
        """

        await self.db_pool.simple_upsert_many(
            table="users_in_public_rooms",
            key_names=["user_id", "room_id"],
            key_values=[(user_id, room_id) for user_id in user_ids],
            value_names=(),
            value_values=(),
            desc="add_users_in_public_rooms",
        )

    async def delete_all_from_user_dir(self) -> None:
        """Delete the entire user directory"""

        def _delete_all_from_user_dir_txn(txn: LoggingTransaction) -> None:
            txn.execute("DELETE FROM user_directory")
            txn.execute("DELETE FROM user_directory_search")
            txn.execute("DELETE FROM users_in_public_rooms")
            txn.execute("DELETE FROM users_who_share_private_rooms")
            txn.call_after(self.get_user_in_directory.invalidate_all)

        await self.db_pool.runInteraction(
            "delete_all_from_user_dir", _delete_all_from_user_dir_txn
        )

    @cached()
    async def get_user_in_directory(self, user_id: str) -> Optional[Dict[str, str]]:
        return await self.db_pool.simple_select_one(
            table="user_directory",
            keyvalues={"user_id": user_id},
            retcols=("display_name", "avatar_url"),
            allow_none=True,
            desc="get_user_in_directory",
        )

    async def update_user_directory_stream_pos(self, stream_id: Optional[int]) -> None:
        await self.db_pool.simple_update_one(
            table="user_directory_stream_pos",
            keyvalues={},
            updatevalues={"stream_id": stream_id},
            desc="update_user_directory_stream_pos",
        )


class SearchResult(TypedDict):
    limited: bool
    results: List[UserProfile]


class UserDirectoryStore(UserDirectoryBackgroundUpdateStore):
    # How many records do we calculate before sending it to
    # add_users_who_share_private_rooms?
    SHARE_PRIVATE_WORKING_SET = 500

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ) -> None:
        super().__init__(database, db_conn, hs)

        self._prefer_local_users_in_search = (
            hs.config.userdirectory.user_directory_search_prefer_local_users
        )
        self._server_name = hs.config.server.server_name

    async def remove_from_user_dir(self, user_id: str) -> None:
        def _remove_from_user_dir_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_delete_txn(
                txn, table="user_directory", keyvalues={"user_id": user_id}
            )
            self.db_pool.simple_delete_txn(
                txn, table="user_directory_search", keyvalues={"user_id": user_id}
            )
            self.db_pool.simple_delete_txn(
                txn, table="users_in_public_rooms", keyvalues={"user_id": user_id}
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"user_id": user_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"other_user_id": user_id},
            )
            txn.call_after(self.get_user_in_directory.invalidate, (user_id,))

        await self.db_pool.runInteraction(
            "remove_from_user_dir", _remove_from_user_dir_txn
        )

    async def get_users_in_dir_due_to_room(self, room_id: str) -> Set[str]:
        """Get all user_ids that are in the room directory because they're
        in the given room_id
        """
        user_ids_share_pub = await self.db_pool.simple_select_onecol(
            table="users_in_public_rooms",
            keyvalues={"room_id": room_id},
            retcol="user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids_share_priv = await self.db_pool.simple_select_onecol(
            table="users_who_share_private_rooms",
            keyvalues={"room_id": room_id},
            retcol="other_user_id",
            desc="get_users_in_dir_due_to_room",
        )

        user_ids = set(user_ids_share_pub)
        user_ids.update(user_ids_share_priv)

        return user_ids

    async def remove_user_who_share_room(self, user_id: str, room_id: str) -> None:
        """
        Deletes entries in the users_who_share_*_rooms table. The first
        user should be a local user.

        Args:
            user_id
            room_id
        """

        def _remove_user_who_share_room_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"user_id": user_id, "room_id": room_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="users_who_share_private_rooms",
                keyvalues={"other_user_id": user_id, "room_id": room_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="users_in_public_rooms",
                keyvalues={"user_id": user_id, "room_id": room_id},
            )

        await self.db_pool.runInteraction(
            "remove_user_who_share_room", _remove_user_who_share_room_txn
        )

    async def get_user_dir_rooms_user_is_in(self, user_id: str) -> List[str]:
        """
        Returns the rooms that a user is in.

        Args:
            user_id(str): Must be a local user

        Returns:
            list: user_id
        """
        rows = await self.db_pool.simple_select_onecol(
            table="users_who_share_private_rooms",
            keyvalues={"user_id": user_id},
            retcol="room_id",
            desc="get_rooms_user_is_in",
        )

        pub_rows = await self.db_pool.simple_select_onecol(
            table="users_in_public_rooms",
            keyvalues={"user_id": user_id},
            retcol="room_id",
            desc="get_rooms_user_is_in",
        )

        users = set(pub_rows)
        users.update(rows)
        return list(users)

    async def get_user_directory_stream_pos(self) -> Optional[int]:
        """
        Get the stream ID of the user directory stream.

        Returns:
            The stream token or None if the initial background update hasn't happened yet.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="user_directory_stream_pos",
            keyvalues={},
            retcol="stream_id",
            desc="get_user_directory_stream_pos",
        )

    async def search_user_dir(
        self, user_id: str, search_term: str, limit: int
    ) -> SearchResult:
        """Searches for users in directory

        Returns:
            dict of the form::

                {
                    "limited": <bool>,  # whether there were more results or not
                    "results": [  # Ordered by best match first
                        {
                            "user_id": <user_id>,
                            "display_name": <display_name>,
                            "avatar_url": <avatar_url>
                        }
                    ]
                }
        """

        if self.hs.config.userdirectory.user_directory_search_all_users:
            join_args = (user_id,)
            where_clause = "user_id != ?"
        else:
            join_args = (user_id,)
            where_clause = """
                (
                    EXISTS (select 1 from users_in_public_rooms WHERE user_id = t.user_id)
                    OR EXISTS (
                        SELECT 1 FROM users_who_share_private_rooms
                        WHERE user_id = ? AND other_user_id = t.user_id
                    )
                )
            """

        # We allow manipulating the ranking algorithm by injecting statements
        # based on config options.
        additional_ordering_statements = []
        ordering_arguments: Tuple[str, ...] = ()

        if isinstance(self.database_engine, PostgresEngine):
            full_query, exact_query, prefix_query = _parse_query_postgres(search_term)

            # If enabled, this config option will rank local users higher than those on
            # remote instances.
            if self._prefer_local_users_in_search:
                # This statement checks whether a given user's user ID contains a server name
                # that matches the local server
                statement = "* (CASE WHEN user_id LIKE ? THEN 2.0 ELSE 1.0 END)"
                additional_ordering_statements.append(statement)

                ordering_arguments += ("%:" + self._server_name,)

            # We order by rank and then if they have profile info
            # The ranking algorithm is hand tweaked for "best" results. Broadly
            # the idea is we give a higher weight to exact matches.
            # The array of numbers are the weights for the various part of the
            # search: (domain, _, display name, localpart)
            sql = """
                SELECT d.user_id AS user_id, display_name, avatar_url
                FROM user_directory_search as t
                INNER JOIN user_directory AS d USING (user_id)
                WHERE
                    %(where_clause)s
                    AND vector @@ to_tsquery('simple', ?)
                ORDER BY
                    (CASE WHEN d.user_id IS NOT NULL THEN 4.0 ELSE 1.0 END)
                    * (CASE WHEN display_name IS NOT NULL THEN 1.2 ELSE 1.0 END)
                    * (CASE WHEN avatar_url IS NOT NULL THEN 1.2 ELSE 1.0 END)
                    * (
                        3 * ts_rank_cd(
                            '{0.1, 0.1, 0.9, 1.0}',
                            vector,
                            to_tsquery('simple', ?),
                            8
                        )
                        + ts_rank_cd(
                            '{0.1, 0.1, 0.9, 1.0}',
                            vector,
                            to_tsquery('simple', ?),
                            8
                        )
                    )
                    %(order_case_statements)s
                    DESC,
                    display_name IS NULL,
                    avatar_url IS NULL
                LIMIT ?
            """ % {
                "where_clause": where_clause,
                "order_case_statements": " ".join(additional_ordering_statements),
            }
            args = (
                join_args
                + (full_query, exact_query, prefix_query)
                + ordering_arguments
                + (limit + 1,)
            )
        elif isinstance(self.database_engine, Sqlite3Engine):
            search_query = _parse_query_sqlite(search_term)

            # If enabled, this config option will rank local users higher than those on
            # remote instances.
            if self._prefer_local_users_in_search:
                # This statement checks whether a given user's user ID contains a server name
                # that matches the local server
                #
                # Note that we need to include a comma at the end for valid SQL
                statement = "user_id LIKE ? DESC,"
                additional_ordering_statements.append(statement)

                ordering_arguments += ("%:" + self._server_name,)

            sql = """
                SELECT d.user_id AS user_id, display_name, avatar_url
                FROM user_directory_search as t
                INNER JOIN user_directory AS d USING (user_id)
                WHERE
                    %(where_clause)s
                    AND value MATCH ?
                ORDER BY
                    rank(matchinfo(user_directory_search)) DESC,
                    %(order_statements)s
                    display_name IS NULL,
                    avatar_url IS NULL
                LIMIT ?
            """ % {
                "where_clause": where_clause,
                "order_statements": " ".join(additional_ordering_statements),
            }
            args = join_args + (search_query,) + ordering_arguments + (limit + 1,)
        else:
            # This should be unreachable.
            raise Exception("Unrecognized database engine")

        results = cast(
            List[UserProfile],
            await self.db_pool.execute(
                "search_user_dir", self.db_pool.cursor_to_dict, sql, *args
            ),
        )

        limited = len(results) > limit

        return {"limited": limited, "results": results}


def _parse_query_sqlite(search_term: str) -> str:
    """Takes a plain unicode string from the user and converts it into a form
    that can be passed to database.
    We use this so that we can add prefix matching, which isn't something
    that is supported by default.

    We specifically add both a prefix and non prefix matching term so that
    exact matches get ranked higher.
    """

    # Pull out the individual words, discarding any non-word characters.
    results = re.findall(r"([\w\-]+)", search_term, re.UNICODE)
    return " & ".join("(%s* OR %s)" % (result, result) for result in results)


def _parse_query_postgres(search_term: str) -> Tuple[str, str, str]:
    """Takes a plain unicode string from the user and converts it into a form
    that can be passed to database.
    We use this so that we can add prefix matching, which isn't something
    that is supported by default.
    """

    # Pull out the individual words, discarding any non-word characters.
    results = re.findall(r"([\w\-]+)", search_term, re.UNICODE)

    both = " & ".join("(%s:* | %s)" % (result, result) for result in results)
    exact = " & ".join("%s" % (result,) for result in results)
    prefix = " & ".join("%s:*" % (result,) for result in results)

    return both, exact, prefix

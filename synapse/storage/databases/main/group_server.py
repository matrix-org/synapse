# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

from typing import Any, Dict, List, Optional, Tuple

from typing_extensions import TypedDict

from synapse.api.errors import SynapseError
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.types import JsonDict
from synapse.util import json_encoder

# The category ID for the "default" category. We don't store as null in the
# database to avoid the fun of null != null
_DEFAULT_CATEGORY_ID = ""
_DEFAULT_ROLE_ID = ""

# A room in a group.
_RoomInGroup = TypedDict("_RoomInGroup", {"room_id": str, "is_public": bool})


class GroupServerWorkerStore(SQLBaseStore):
    async def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        return await self.db_pool.simple_select_one(
            table="groups",
            keyvalues={"group_id": group_id},
            retcols=(
                "name",
                "short_description",
                "long_description",
                "avatar_url",
                "is_public",
                "join_policy",
            ),
            allow_none=True,
            desc="get_group",
        )

    async def get_users_in_group(
        self, group_id: str, include_private: bool = False
    ) -> List[Dict[str, Any]]:
        # TODO: Pagination

        keyvalues = {"group_id": group_id}
        if not include_private:
            keyvalues["is_public"] = True

        return await self.db_pool.simple_select_list(
            table="group_users",
            keyvalues=keyvalues,
            retcols=("user_id", "is_public", "is_admin"),
            desc="get_users_in_group",
        )

    async def get_invited_users_in_group(self, group_id: str) -> List[str]:
        # TODO: Pagination

        return await self.db_pool.simple_select_onecol(
            table="group_invites",
            keyvalues={"group_id": group_id},
            retcol="user_id",
            desc="get_invited_users_in_group",
        )

    async def get_rooms_in_group(
        self, group_id: str, include_private: bool = False
    ) -> List[_RoomInGroup]:
        """Retrieve the rooms that belong to a given group. Does not return rooms that
        lack members.

        Args:
            group_id: The ID of the group to query for rooms
            include_private: Whether to return private rooms in results

        Returns:
            A list of dictionaries, each in the form of:

            {
              "room_id": "!a_room_id:example.com",  # The ID of the room
              "is_public": False                    # Whether this is a public room or not
            }
        """
        # TODO: Pagination

        def _get_rooms_in_group_txn(txn):
            sql = """
            SELECT room_id, is_public FROM group_rooms
                WHERE group_id = ?
                AND room_id IN (
                    SELECT group_rooms.room_id FROM group_rooms
                    LEFT JOIN room_stats_current ON
                        group_rooms.room_id = room_stats_current.room_id
                        AND joined_members > 0
                        AND local_users_in_room > 0
                    LEFT JOIN rooms ON
                        group_rooms.room_id = rooms.room_id
                        AND (room_version <> '') = ?
                )
            """
            args = [group_id, False]

            if not include_private:
                sql += " AND is_public = ?"
                args += [True]

            txn.execute(sql, args)

            return [
                {"room_id": room_id, "is_public": is_public}
                for room_id, is_public in txn
            ]

        return await self.db_pool.runInteraction(
            "get_rooms_in_group", _get_rooms_in_group_txn
        )

    async def get_rooms_for_summary_by_category(
        self,
        group_id: str,
        include_private: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Get the rooms and categories that should be included in a summary request

        Args:
            group_id: The ID of the group to query the summary for
            include_private: Whether to return private rooms in results

        Returns:
            A tuple containing:

                * A list of dictionaries with the keys:
                    * "room_id": str, the room ID
                    * "is_public": bool, whether the room is public
                    * "category_id": str|None, the category ID if set, else None
                    * "order": int, the sort order of rooms

                * A dictionary with the key:
                    * category_id (str): a dictionary with the keys:
                        * "is_public": bool, whether the category is public
                        * "profile": str, the category profile
                        * "order": int, the sort order of rooms in this category
        """

        def _get_rooms_for_summary_txn(txn):
            keyvalues = {"group_id": group_id}
            if not include_private:
                keyvalues["is_public"] = True

            sql = """
                SELECT room_id, is_public, category_id, room_order
                FROM group_summary_rooms
                WHERE group_id = ?
                AND room_id IN (
                    SELECT group_rooms.room_id FROM group_rooms
                    LEFT JOIN room_stats_current ON
                        group_rooms.room_id = room_stats_current.room_id
                        AND joined_members > 0
                        AND local_users_in_room > 0
                    LEFT JOIN rooms ON
                        group_rooms.room_id = rooms.room_id
                        AND (room_version <> '') = ?
                )
            """

            if not include_private:
                sql += " AND is_public = ?"
                txn.execute(sql, (group_id, False, True))
            else:
                txn.execute(sql, (group_id, False))

            rooms = [
                {
                    "room_id": row[0],
                    "is_public": row[1],
                    "category_id": row[2] if row[2] != _DEFAULT_CATEGORY_ID else None,
                    "order": row[3],
                }
                for row in txn
            ]

            sql = """
                SELECT category_id, is_public, profile, cat_order
                FROM group_summary_room_categories
                INNER JOIN group_room_categories USING (group_id, category_id)
                WHERE group_id = ?
            """

            if not include_private:
                sql += " AND is_public = ?"
                txn.execute(sql, (group_id, True))
            else:
                txn.execute(sql, (group_id,))

            categories = {
                row[0]: {
                    "is_public": row[1],
                    "profile": db_to_json(row[2]),
                    "order": row[3],
                }
                for row in txn
            }

            return rooms, categories

        return await self.db_pool.runInteraction(
            "get_rooms_for_summary", _get_rooms_for_summary_txn
        )

    async def get_group_categories(self, group_id):
        rows = await self.db_pool.simple_select_list(
            table="group_room_categories",
            keyvalues={"group_id": group_id},
            retcols=("category_id", "is_public", "profile"),
            desc="get_group_categories",
        )

        return {
            row["category_id"]: {
                "is_public": row["is_public"],
                "profile": db_to_json(row["profile"]),
            }
            for row in rows
        }

    async def get_group_category(self, group_id, category_id):
        category = await self.db_pool.simple_select_one(
            table="group_room_categories",
            keyvalues={"group_id": group_id, "category_id": category_id},
            retcols=("is_public", "profile"),
            desc="get_group_category",
        )

        category["profile"] = db_to_json(category["profile"])

        return category

    async def get_group_roles(self, group_id):
        rows = await self.db_pool.simple_select_list(
            table="group_roles",
            keyvalues={"group_id": group_id},
            retcols=("role_id", "is_public", "profile"),
            desc="get_group_roles",
        )

        return {
            row["role_id"]: {
                "is_public": row["is_public"],
                "profile": db_to_json(row["profile"]),
            }
            for row in rows
        }

    async def get_group_role(self, group_id, role_id):
        role = await self.db_pool.simple_select_one(
            table="group_roles",
            keyvalues={"group_id": group_id, "role_id": role_id},
            retcols=("is_public", "profile"),
            desc="get_group_role",
        )

        role["profile"] = db_to_json(role["profile"])

        return role

    async def get_local_groups_for_room(self, room_id: str) -> List[str]:
        """Get all of the local group that contain a given room
        Args:
            room_id: The ID of a room
        Returns:
            A list of group ids containing this room
        """
        return await self.db_pool.simple_select_onecol(
            table="group_rooms",
            keyvalues={"room_id": room_id},
            retcol="group_id",
            desc="get_local_groups_for_room",
        )

    async def get_users_for_summary_by_role(self, group_id, include_private=False):
        """Get the users and roles that should be included in a summary request

        Returns:
            ([users], [roles])
        """

        def _get_users_for_summary_txn(txn):
            keyvalues = {"group_id": group_id}
            if not include_private:
                keyvalues["is_public"] = True

            sql = """
                SELECT user_id, is_public, role_id, user_order
                FROM group_summary_users
                WHERE group_id = ?
            """

            if not include_private:
                sql += " AND is_public = ?"
                txn.execute(sql, (group_id, True))
            else:
                txn.execute(sql, (group_id,))

            users = [
                {
                    "user_id": row[0],
                    "is_public": row[1],
                    "role_id": row[2] if row[2] != _DEFAULT_ROLE_ID else None,
                    "order": row[3],
                }
                for row in txn
            ]

            sql = """
                SELECT role_id, is_public, profile, role_order
                FROM group_summary_roles
                INNER JOIN group_roles USING (group_id, role_id)
                WHERE group_id = ?
            """

            if not include_private:
                sql += " AND is_public = ?"
                txn.execute(sql, (group_id, True))
            else:
                txn.execute(sql, (group_id,))

            roles = {
                row[0]: {
                    "is_public": row[1],
                    "profile": db_to_json(row[2]),
                    "order": row[3],
                }
                for row in txn
            }

            return users, roles

        return await self.db_pool.runInteraction(
            "get_users_for_summary_by_role", _get_users_for_summary_txn
        )

    async def is_user_in_group(self, user_id: str, group_id: str) -> bool:
        result = await self.db_pool.simple_select_one_onecol(
            table="group_users",
            keyvalues={"group_id": group_id, "user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="is_user_in_group",
        )
        return bool(result)

    async def is_user_admin_in_group(
        self, group_id: str, user_id: str
    ) -> Optional[bool]:
        return await self.db_pool.simple_select_one_onecol(
            table="group_users",
            keyvalues={"group_id": group_id, "user_id": user_id},
            retcol="is_admin",
            allow_none=True,
            desc="is_user_admin_in_group",
        )

    async def is_user_invited_to_local_group(
        self, group_id: str, user_id: str
    ) -> Optional[bool]:
        """Has the group server invited a user?"""
        return await self.db_pool.simple_select_one_onecol(
            table="group_invites",
            keyvalues={"group_id": group_id, "user_id": user_id},
            retcol="user_id",
            desc="is_user_invited_to_local_group",
            allow_none=True,
        )

    async def get_users_membership_info_in_group(self, group_id, user_id):
        """Get a dict describing the membership of a user in a group.

        Example if joined:

            {
                "membership": "join",
                "is_public": True,
                "is_privileged": False,
            }

        Returns:
             An empty dict if the user is not join/invite/etc
        """

        def _get_users_membership_in_group_txn(txn):
            row = self.db_pool.simple_select_one_txn(
                txn,
                table="group_users",
                keyvalues={"group_id": group_id, "user_id": user_id},
                retcols=("is_admin", "is_public"),
                allow_none=True,
            )

            if row:
                return {
                    "membership": "join",
                    "is_public": row["is_public"],
                    "is_privileged": row["is_admin"],
                }

            row = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="group_invites",
                keyvalues={"group_id": group_id, "user_id": user_id},
                retcol="user_id",
                allow_none=True,
            )

            if row:
                return {"membership": "invite"}

            return {}

        return await self.db_pool.runInteraction(
            "get_users_membership_info_in_group", _get_users_membership_in_group_txn
        )

    async def get_publicised_groups_for_user(self, user_id: str) -> List[str]:
        """Get all groups a user is publicising"""
        return await self.db_pool.simple_select_onecol(
            table="local_group_membership",
            keyvalues={"user_id": user_id, "membership": "join", "is_publicised": True},
            retcol="group_id",
            desc="get_publicised_groups_for_user",
        )

    async def get_attestations_need_renewals(self, valid_until_ms):
        """Get all attestations that need to be renewed until givent time"""

        def _get_attestations_need_renewals_txn(txn):
            sql = """
                SELECT group_id, user_id FROM group_attestations_renewals
                WHERE valid_until_ms <= ?
            """
            txn.execute(sql, (valid_until_ms,))
            return self.db_pool.cursor_to_dict(txn)

        return await self.db_pool.runInteraction(
            "get_attestations_need_renewals", _get_attestations_need_renewals_txn
        )

    async def get_remote_attestation(self, group_id, user_id):
        """Get the attestation that proves the remote agrees that the user is
        in the group.
        """
        row = await self.db_pool.simple_select_one(
            table="group_attestations_remote",
            keyvalues={"group_id": group_id, "user_id": user_id},
            retcols=("valid_until_ms", "attestation_json"),
            desc="get_remote_attestation",
            allow_none=True,
        )

        now = int(self._clock.time_msec())
        if row and now < row["valid_until_ms"]:
            return db_to_json(row["attestation_json"])

        return None

    async def get_joined_groups(self, user_id: str) -> List[str]:
        return await self.db_pool.simple_select_onecol(
            table="local_group_membership",
            keyvalues={"user_id": user_id, "membership": "join"},
            retcol="group_id",
            desc="get_joined_groups",
        )

    async def get_all_groups_for_user(self, user_id, now_token):
        def _get_all_groups_for_user_txn(txn):
            sql = """
                SELECT group_id, type, membership, u.content
                FROM local_group_updates AS u
                INNER JOIN local_group_membership USING (group_id, user_id)
                WHERE user_id = ? AND membership != 'leave'
                    AND stream_id <= ?
            """
            txn.execute(sql, (user_id, now_token))
            return [
                {
                    "group_id": row[0],
                    "type": row[1],
                    "membership": row[2],
                    "content": db_to_json(row[3]),
                }
                for row in txn
            ]

        return await self.db_pool.runInteraction(
            "get_all_groups_for_user", _get_all_groups_for_user_txn
        )

    async def get_groups_changes_for_user(self, user_id, from_token, to_token):
        from_token = int(from_token)
        has_changed = self._group_updates_stream_cache.has_entity_changed(
            user_id, from_token
        )
        if not has_changed:
            return []

        def _get_groups_changes_for_user_txn(txn):
            sql = """
                SELECT group_id, membership, type, u.content
                FROM local_group_updates AS u
                INNER JOIN local_group_membership USING (group_id, user_id)
                WHERE user_id = ? AND ? < stream_id AND stream_id <= ?
            """
            txn.execute(sql, (user_id, from_token, to_token))
            return [
                {
                    "group_id": group_id,
                    "membership": membership,
                    "type": gtype,
                    "content": db_to_json(content_json),
                }
                for group_id, membership, gtype, content_json in txn
            ]

        return await self.db_pool.runInteraction(
            "get_groups_changes_for_user", _get_groups_changes_for_user_txn
        )

    async def get_all_groups_changes(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, tuple]], int, bool]:
        """Get updates for groups replication stream.

        Args:
            instance_name: The writer we want to fetch updates from. Unused
                here since there is only ever one writer.
            last_id: The token to fetch updates from. Exclusive.
            current_id: The token to fetch updates up to. Inclusive.
            limit: The requested limit for the number of rows to return. The
                function may return more or fewer rows.

        Returns:
            A tuple consisting of: the updates, a token to use to fetch
            subsequent updates, and whether we returned fewer rows than exists
            between the requested tokens due to the limit.

            The token returned can be used in a subsequent call to this
            function to get further updatees.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        last_id = int(last_id)
        has_changed = self._group_updates_stream_cache.has_any_entity_changed(last_id)

        if not has_changed:
            return [], current_id, False

        def _get_all_groups_changes_txn(txn):
            sql = """
                SELECT stream_id, group_id, user_id, type, content
                FROM local_group_updates
                WHERE ? < stream_id AND stream_id <= ?
                LIMIT ?
            """
            txn.execute(sql, (last_id, current_id, limit))
            updates = [
                (stream_id, (group_id, user_id, gtype, db_to_json(content_json)))
                for stream_id, group_id, user_id, gtype, content_json in txn
            ]

            limited = False
            upto_token = current_id
            if len(updates) >= limit:
                upto_token = updates[-1][0]
                limited = True

            return updates, upto_token, limited

        return await self.db_pool.runInteraction(
            "get_all_groups_changes", _get_all_groups_changes_txn
        )


class GroupServerStore(GroupServerWorkerStore):
    async def set_group_join_policy(self, group_id: str, join_policy: str) -> None:
        """Set the join policy of a group.

        join_policy can be one of:
         * "invite"
         * "open"
        """
        await self.db_pool.simple_update_one(
            table="groups",
            keyvalues={"group_id": group_id},
            updatevalues={"join_policy": join_policy},
            desc="set_group_join_policy",
        )

    async def add_room_to_summary(
        self,
        group_id: str,
        room_id: str,
        category_id: str,
        order: int,
        is_public: Optional[bool],
    ) -> None:
        """Add (or update) room's entry in summary.

        Args:
            group_id
            room_id
            category_id: If not None then adds the category to the end of
                the summary if its not already there.
            order: If not None inserts the room at that position, e.g. an order
                of 1 will put the room first. Otherwise, the room gets added to
                the end.
            is_public
        """
        await self.db_pool.runInteraction(
            "add_room_to_summary",
            self._add_room_to_summary_txn,
            group_id,
            room_id,
            category_id,
            order,
            is_public,
        )

    def _add_room_to_summary_txn(
        self,
        txn,
        group_id: str,
        room_id: str,
        category_id: str,
        order: int,
        is_public: Optional[bool],
    ) -> None:
        """Add (or update) room's entry in summary.

        Args:
            txn
            group_id
            room_id
            category_id: If not None then adds the category to the end of
                the summary if its not already there.
            order: If not None inserts the room at that position, e.g. an order
                of 1 will put the room first. Otherwise, the room gets added to
                the end.
            is_public
        """
        room_in_group = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="group_rooms",
            keyvalues={"group_id": group_id, "room_id": room_id},
            retcol="room_id",
            allow_none=True,
        )
        if not room_in_group:
            raise SynapseError(400, "room not in group")

        if category_id is None:
            category_id = _DEFAULT_CATEGORY_ID
        else:
            cat_exists = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="group_room_categories",
                keyvalues={"group_id": group_id, "category_id": category_id},
                retcol="group_id",
                allow_none=True,
            )
            if not cat_exists:
                raise SynapseError(400, "Category doesn't exist")

            # TODO: Check category is part of summary already
            cat_exists = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="group_summary_room_categories",
                keyvalues={"group_id": group_id, "category_id": category_id},
                retcol="group_id",
                allow_none=True,
            )
            if not cat_exists:
                # If not, add it with an order larger than all others
                txn.execute(
                    """
                    INSERT INTO group_summary_room_categories
                    (group_id, category_id, cat_order)
                    SELECT ?, ?, COALESCE(MAX(cat_order), 0) + 1
                    FROM group_summary_room_categories
                    WHERE group_id = ? AND category_id = ?
                """,
                    (group_id, category_id, group_id, category_id),
                )

        existing = self.db_pool.simple_select_one_txn(
            txn,
            table="group_summary_rooms",
            keyvalues={
                "group_id": group_id,
                "room_id": room_id,
                "category_id": category_id,
            },
            retcols=("room_order", "is_public"),
            allow_none=True,
        )

        if order is not None:
            # Shuffle other room orders that come after the given order
            sql = """
                UPDATE group_summary_rooms SET room_order = room_order + 1
                WHERE group_id = ? AND category_id = ? AND room_order >= ?
            """
            txn.execute(sql, (group_id, category_id, order))
        elif not existing:
            sql = """
                SELECT COALESCE(MAX(room_order), 0) + 1 FROM group_summary_rooms
                WHERE group_id = ? AND category_id = ?
            """
            txn.execute(sql, (group_id, category_id))
            (order,) = txn.fetchone()

        if existing:
            to_update = {}
            if order is not None:
                to_update["room_order"] = order
            if is_public is not None:
                to_update["is_public"] = is_public
            self.db_pool.simple_update_txn(
                txn,
                table="group_summary_rooms",
                keyvalues={
                    "group_id": group_id,
                    "category_id": category_id,
                    "room_id": room_id,
                },
                values=to_update,
            )
        else:
            if is_public is None:
                is_public = True

            self.db_pool.simple_insert_txn(
                txn,
                table="group_summary_rooms",
                values={
                    "group_id": group_id,
                    "category_id": category_id,
                    "room_id": room_id,
                    "room_order": order,
                    "is_public": is_public,
                },
            )

    async def remove_room_from_summary(
        self, group_id: str, room_id: str, category_id: str
    ) -> int:
        if category_id is None:
            category_id = _DEFAULT_CATEGORY_ID

        return await self.db_pool.simple_delete(
            table="group_summary_rooms",
            keyvalues={
                "group_id": group_id,
                "category_id": category_id,
                "room_id": room_id,
            },
            desc="remove_room_from_summary",
        )

    async def upsert_group_category(
        self,
        group_id: str,
        category_id: str,
        profile: Optional[JsonDict],
        is_public: Optional[bool],
    ) -> None:
        """Add/update room category for group"""
        insertion_values = {}
        update_values = {"category_id": category_id}  # This cannot be empty

        if profile is None:
            insertion_values["profile"] = "{}"
        else:
            update_values["profile"] = json_encoder.encode(profile)

        if is_public is None:
            insertion_values["is_public"] = True
        else:
            update_values["is_public"] = is_public

        await self.db_pool.simple_upsert(
            table="group_room_categories",
            keyvalues={"group_id": group_id, "category_id": category_id},
            values=update_values,
            insertion_values=insertion_values,
            desc="upsert_group_category",
        )

    async def remove_group_category(self, group_id: str, category_id: str) -> int:
        return await self.db_pool.simple_delete(
            table="group_room_categories",
            keyvalues={"group_id": group_id, "category_id": category_id},
            desc="remove_group_category",
        )

    async def upsert_group_role(
        self,
        group_id: str,
        role_id: str,
        profile: Optional[JsonDict],
        is_public: Optional[bool],
    ) -> None:
        """Add/remove user role"""
        insertion_values = {}
        update_values = {"role_id": role_id}  # This cannot be empty

        if profile is None:
            insertion_values["profile"] = "{}"
        else:
            update_values["profile"] = json_encoder.encode(profile)

        if is_public is None:
            insertion_values["is_public"] = True
        else:
            update_values["is_public"] = is_public

        await self.db_pool.simple_upsert(
            table="group_roles",
            keyvalues={"group_id": group_id, "role_id": role_id},
            values=update_values,
            insertion_values=insertion_values,
            desc="upsert_group_role",
        )

    async def remove_group_role(self, group_id: str, role_id: str) -> int:
        return await self.db_pool.simple_delete(
            table="group_roles",
            keyvalues={"group_id": group_id, "role_id": role_id},
            desc="remove_group_role",
        )

    async def add_user_to_summary(
        self,
        group_id: str,
        user_id: str,
        role_id: str,
        order: int,
        is_public: Optional[bool],
    ) -> None:
        """Add (or update) user's entry in summary.

        Args:
            group_id
            user_id
            role_id: If not None then adds the role to the end of the summary if
                its not already there.
            order: If not None inserts the user at that position, e.g. an order
                of 1 will put the user first. Otherwise, the user gets added to
                the end.
            is_public
        """
        await self.db_pool.runInteraction(
            "add_user_to_summary",
            self._add_user_to_summary_txn,
            group_id,
            user_id,
            role_id,
            order,
            is_public,
        )

    def _add_user_to_summary_txn(
        self,
        txn,
        group_id: str,
        user_id: str,
        role_id: str,
        order: int,
        is_public: Optional[bool],
    ):
        """Add (or update) user's entry in summary.

        Args:
            txn
            group_id
            user_id
            role_id: If not None then adds the role to the end of the summary if
                its not already there.
            order: If not None inserts the user at that position, e.g. an order
                of 1 will put the user first. Otherwise, the user gets added to
                the end.
            is_public
        """
        user_in_group = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="group_users",
            keyvalues={"group_id": group_id, "user_id": user_id},
            retcol="user_id",
            allow_none=True,
        )
        if not user_in_group:
            raise SynapseError(400, "user not in group")

        if role_id is None:
            role_id = _DEFAULT_ROLE_ID
        else:
            role_exists = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="group_roles",
                keyvalues={"group_id": group_id, "role_id": role_id},
                retcol="group_id",
                allow_none=True,
            )
            if not role_exists:
                raise SynapseError(400, "Role doesn't exist")

            # TODO: Check role is part of the summary already
            role_exists = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="group_summary_roles",
                keyvalues={"group_id": group_id, "role_id": role_id},
                retcol="group_id",
                allow_none=True,
            )
            if not role_exists:
                # If not, add it with an order larger than all others
                txn.execute(
                    """
                    INSERT INTO group_summary_roles
                    (group_id, role_id, role_order)
                    SELECT ?, ?, COALESCE(MAX(role_order), 0) + 1
                    FROM group_summary_roles
                    WHERE group_id = ? AND role_id = ?
                """,
                    (group_id, role_id, group_id, role_id),
                )

        existing = self.db_pool.simple_select_one_txn(
            txn,
            table="group_summary_users",
            keyvalues={"group_id": group_id, "user_id": user_id, "role_id": role_id},
            retcols=("user_order", "is_public"),
            allow_none=True,
        )

        if order is not None:
            # Shuffle other users orders that come after the given order
            sql = """
                UPDATE group_summary_users SET user_order = user_order + 1
                WHERE group_id = ? AND role_id = ? AND user_order >= ?
            """
            txn.execute(sql, (group_id, role_id, order))
        elif not existing:
            sql = """
                SELECT COALESCE(MAX(user_order), 0) + 1 FROM group_summary_users
                WHERE group_id = ? AND role_id = ?
            """
            txn.execute(sql, (group_id, role_id))
            (order,) = txn.fetchone()

        if existing:
            to_update = {}
            if order is not None:
                to_update["user_order"] = order
            if is_public is not None:
                to_update["is_public"] = is_public
            self.db_pool.simple_update_txn(
                txn,
                table="group_summary_users",
                keyvalues={
                    "group_id": group_id,
                    "role_id": role_id,
                    "user_id": user_id,
                },
                values=to_update,
            )
        else:
            if is_public is None:
                is_public = True

            self.db_pool.simple_insert_txn(
                txn,
                table="group_summary_users",
                values={
                    "group_id": group_id,
                    "role_id": role_id,
                    "user_id": user_id,
                    "user_order": order,
                    "is_public": is_public,
                },
            )

    async def remove_user_from_summary(
        self, group_id: str, user_id: str, role_id: str
    ) -> int:
        if role_id is None:
            role_id = _DEFAULT_ROLE_ID

        return await self.db_pool.simple_delete(
            table="group_summary_users",
            keyvalues={"group_id": group_id, "role_id": role_id, "user_id": user_id},
            desc="remove_user_from_summary",
        )

    async def add_group_invite(self, group_id: str, user_id: str) -> None:
        """Record that the group server has invited a user"""
        await self.db_pool.simple_insert(
            table="group_invites",
            values={"group_id": group_id, "user_id": user_id},
            desc="add_group_invite",
        )

    async def add_user_to_group(
        self,
        group_id: str,
        user_id: str,
        is_admin: bool = False,
        is_public: bool = True,
        local_attestation: Optional[dict] = None,
        remote_attestation: Optional[dict] = None,
    ) -> None:
        """Add a user to the group server.

        Args:
            group_id
            user_id
            is_admin
            is_public
            local_attestation: The attestation the GS created to give to the remote
                server. Optional if the user and group are on the same server
            remote_attestation: The attestation given to GS by remote server.
                Optional if the user and group are on the same server
        """

        def _add_user_to_group_txn(txn):
            self.db_pool.simple_insert_txn(
                txn,
                table="group_users",
                values={
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "is_public": is_public,
                },
            )

            self.db_pool.simple_delete_txn(
                txn,
                table="group_invites",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )

            if local_attestation:
                self.db_pool.simple_insert_txn(
                    txn,
                    table="group_attestations_renewals",
                    values={
                        "group_id": group_id,
                        "user_id": user_id,
                        "valid_until_ms": local_attestation["valid_until_ms"],
                    },
                )
            if remote_attestation:
                self.db_pool.simple_insert_txn(
                    txn,
                    table="group_attestations_remote",
                    values={
                        "group_id": group_id,
                        "user_id": user_id,
                        "valid_until_ms": remote_attestation["valid_until_ms"],
                        "attestation_json": json_encoder.encode(remote_attestation),
                    },
                )

        await self.db_pool.runInteraction("add_user_to_group", _add_user_to_group_txn)

    async def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        def _remove_user_from_group_txn(txn):
            self.db_pool.simple_delete_txn(
                txn,
                table="group_users",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="group_invites",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="group_attestations_renewals",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="group_attestations_remote",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="group_summary_users",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )

        await self.db_pool.runInteraction(
            "remove_user_from_group", _remove_user_from_group_txn
        )

    async def add_room_to_group(
        self, group_id: str, room_id: str, is_public: bool
    ) -> None:
        await self.db_pool.simple_insert(
            table="group_rooms",
            values={"group_id": group_id, "room_id": room_id, "is_public": is_public},
            desc="add_room_to_group",
        )

    async def update_room_in_group_visibility(
        self, group_id: str, room_id: str, is_public: bool
    ) -> int:
        return await self.db_pool.simple_update(
            table="group_rooms",
            keyvalues={"group_id": group_id, "room_id": room_id},
            updatevalues={"is_public": is_public},
            desc="update_room_in_group_visibility",
        )

    async def remove_room_from_group(self, group_id: str, room_id: str) -> None:
        def _remove_room_from_group_txn(txn):
            self.db_pool.simple_delete_txn(
                txn,
                table="group_rooms",
                keyvalues={"group_id": group_id, "room_id": room_id},
            )

            self.db_pool.simple_delete_txn(
                txn,
                table="group_summary_rooms",
                keyvalues={"group_id": group_id, "room_id": room_id},
            )

        await self.db_pool.runInteraction(
            "remove_room_from_group", _remove_room_from_group_txn
        )

    async def update_group_publicity(
        self, group_id: str, user_id: str, publicise: bool
    ) -> None:
        """Update whether the user is publicising their membership of the group"""
        await self.db_pool.simple_update_one(
            table="local_group_membership",
            keyvalues={"group_id": group_id, "user_id": user_id},
            updatevalues={"is_publicised": publicise},
            desc="update_group_publicity",
        )

    async def register_user_group_membership(
        self,
        group_id: str,
        user_id: str,
        membership: str,
        is_admin: bool = False,
        content: Optional[JsonDict] = None,
        local_attestation: Optional[dict] = None,
        remote_attestation: Optional[dict] = None,
        is_publicised: bool = False,
    ) -> int:
        """Registers that a local user is a member of a (local or remote) group.

        Args:
            group_id: The group the member is being added to.
            user_id: THe user ID to add to the group.
            membership: The type of group membership.
            is_admin: Whether the user should be added as a group admin.
            content: Content of the membership, e.g. includes the inviter
                if the user has been invited.
            local_attestation: If remote group then store the fact that we
                have given out an attestation, else None.
            remote_attestation: If remote group then store the remote
                attestation from the group, else None.
            is_publicised: Whether this should be publicised.
        """

        content = content or {}

        def _register_user_group_membership_txn(txn, next_id):
            # TODO: Upsert?
            self.db_pool.simple_delete_txn(
                txn,
                table="local_group_membership",
                keyvalues={"group_id": group_id, "user_id": user_id},
            )
            self.db_pool.simple_insert_txn(
                txn,
                table="local_group_membership",
                values={
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "membership": membership,
                    "is_publicised": is_publicised,
                    "content": json_encoder.encode(content),
                },
            )

            self.db_pool.simple_insert_txn(
                txn,
                table="local_group_updates",
                values={
                    "stream_id": next_id,
                    "group_id": group_id,
                    "user_id": user_id,
                    "type": "membership",
                    "content": json_encoder.encode(
                        {"membership": membership, "content": content}
                    ),
                },
            )
            self._group_updates_stream_cache.entity_has_changed(user_id, next_id)

            # TODO: Insert profile to ensure it comes down stream if its a join.

            if membership == "join":
                if local_attestation:
                    self.db_pool.simple_insert_txn(
                        txn,
                        table="group_attestations_renewals",
                        values={
                            "group_id": group_id,
                            "user_id": user_id,
                            "valid_until_ms": local_attestation["valid_until_ms"],
                        },
                    )
                if remote_attestation:
                    self.db_pool.simple_insert_txn(
                        txn,
                        table="group_attestations_remote",
                        values={
                            "group_id": group_id,
                            "user_id": user_id,
                            "valid_until_ms": remote_attestation["valid_until_ms"],
                            "attestation_json": json_encoder.encode(remote_attestation),
                        },
                    )
            else:
                self.db_pool.simple_delete_txn(
                    txn,
                    table="group_attestations_renewals",
                    keyvalues={"group_id": group_id, "user_id": user_id},
                )
                self.db_pool.simple_delete_txn(
                    txn,
                    table="group_attestations_remote",
                    keyvalues={"group_id": group_id, "user_id": user_id},
                )

            return next_id

        async with self._group_updates_id_gen.get_next() as next_id:
            res = await self.db_pool.runInteraction(
                "register_user_group_membership",
                _register_user_group_membership_txn,
                next_id,
            )
        return res

    async def create_group(
        self, group_id, user_id, name, avatar_url, short_description, long_description
    ) -> None:
        await self.db_pool.simple_insert(
            table="groups",
            values={
                "group_id": group_id,
                "name": name,
                "avatar_url": avatar_url,
                "short_description": short_description,
                "long_description": long_description,
                "is_public": True,
            },
            desc="create_group",
        )

    async def update_group_profile(self, group_id, profile):
        await self.db_pool.simple_update_one(
            table="groups",
            keyvalues={"group_id": group_id},
            updatevalues=profile,
            desc="update_group_profile",
        )

    async def update_attestation_renewal(
        self, group_id: str, user_id: str, attestation: dict
    ) -> None:
        """Update an attestation that we have renewed"""
        await self.db_pool.simple_update_one(
            table="group_attestations_renewals",
            keyvalues={"group_id": group_id, "user_id": user_id},
            updatevalues={"valid_until_ms": attestation["valid_until_ms"]},
            desc="update_attestation_renewal",
        )

    async def update_remote_attestion(
        self, group_id: str, user_id: str, attestation: dict
    ) -> None:
        """Update an attestation that a remote has renewed"""
        await self.db_pool.simple_update_one(
            table="group_attestations_remote",
            keyvalues={"group_id": group_id, "user_id": user_id},
            updatevalues={
                "valid_until_ms": attestation["valid_until_ms"],
                "attestation_json": json_encoder.encode(attestation),
            },
            desc="update_remote_attestion",
        )

    async def remove_attestation_renewal(self, group_id: str, user_id: str) -> int:
        """Remove an attestation that we thought we should renew, but actually
        shouldn't. Ideally this would never get called as we would never
        incorrectly try and do attestations for local users on local groups.

        Args:
            group_id
            user_id
        """
        return await self.db_pool.simple_delete(
            table="group_attestations_renewals",
            keyvalues={"group_id": group_id, "user_id": user_id},
            desc="remove_attestation_renewal",
        )

    def get_group_stream_token(self):
        return self._group_updates_id_gen.get_current_token()

    async def delete_group(self, group_id: str) -> None:
        """Deletes a group fully from the database.

        Args:
            group_id: The group ID to delete.
        """

        def _delete_group_txn(txn):
            tables = [
                "groups",
                "group_users",
                "group_invites",
                "group_rooms",
                "group_summary_rooms",
                "group_summary_room_categories",
                "group_room_categories",
                "group_summary_users",
                "group_summary_roles",
                "group_roles",
                "group_attestations_renewals",
                "group_attestations_remote",
            ]

            for table in tables:
                self.db_pool.simple_delete_txn(
                    txn, table=table, keyvalues={"group_id": group_id}
                )

        await self.db_pool.runInteraction("delete_group", _delete_group_txn)

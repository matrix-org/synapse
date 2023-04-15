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
from typing import TYPE_CHECKING, Optional

from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.roommember import ProfileInfo
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ProfileWorkerStore(SQLBaseStore):
    async def get_profileinfo(self, user_id: str) -> ProfileInfo:
        try:
            profile = await self.db_pool.simple_select_one(
                table="profiles",
                keyvalues={"full_user_id": user_id},
                retcols=("displayname", "avatar_url"),
                allow_none=True,
                desc="get_profileinfo",
            )
            if profile is None:
                # Fall back to the `user_id` column.
                user_localpart = UserID.from_string(user_id).localpart
                profile = await self.db_pool.simple_select_one(
                    table="profiles",
                    keyvalues={"user_id": user_localpart},
                    retcols=("displayname", "avatar_url"),
                    desc="get_profileinfo",
                )
        except StoreError as e:
            if e.code == 404:
                # no match
                return ProfileInfo(None, None)
            else:
                raise

        return ProfileInfo(
            avatar_url=profile["avatar_url"], display_name=profile["displayname"]
        )

    async def get_profile_displayname(self, user_id: str) -> Optional[str]:
        try:
            return await self.db_pool.simple_select_one_onecol(
                table="profiles",
                keyvalues={"full_user_id": user_id},
                retcol="displayname",
                desc="get_profile_displayname",
            )
        except StoreError as e:
            if e.code == 404:
                # Fall back to the `user_id` column.
                user_localpart = UserID.from_string(user_id).localpart
                return await self.db_pool.simple_select_one_onecol(
                    table="profiles",
                    keyvalues={"user_id": user_localpart},
                    retcol="displayname",
                    desc="get_profile_displayname",
                )
            else:
                raise

    async def get_profile_avatar_url(self, user_id: str) -> Optional[str]:
        try:
            return await self.db_pool.simple_select_one_onecol(
                table="profiles",
                keyvalues={"full_user_id": user_id},
                retcol="avatar_url",
                desc="get_profile_avatar_url",
            )
        except StoreError as e:
            if e.code == 404:
                # Fall back to the `user_id` column.
                user_localpart = UserID.from_string(user_id).localpart
                return await self.db_pool.simple_select_one_onecol(
                    table="profiles",
                    keyvalues={"user_id": user_localpart},
                    retcol="avatar_url",
                    desc="get_profile_avatar_url",
                )
            else:
                raise

    async def create_profile(self, user_id: str) -> None:
        user_localpart = UserID.from_string(user_id).localpart
        await self.db_pool.simple_insert(
            table="profiles",
            values={"user_id": user_localpart, "full_user_id": user_id},
            desc="create_profile",
        )

    async def set_profile_displayname(
        self, user_id: str, new_displayname: Optional[str]
    ) -> None:
        user_localpart = UserID.from_string(user_id).localpart
        await self.db_pool.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"full_user_id": user_id, "displayname": new_displayname},
            desc="set_profile_displayname",
        )

    async def set_profile_avatar_url(
        self, user_localpart: str, new_avatar_url: Optional[str]
    ) -> None:
        await self.db_pool.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"avatar_url": new_avatar_url},
            desc="set_profile_avatar_url",
        )


class ProfileBackgroundUpdateStore(ProfileWorkerStore):
    POPULATE_PROFILES_FULL_USER_ID = "populate_profiles_full_user_id"

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            self.POPULATE_PROFILES_FULL_USER_ID,
            self._populate_profiles_full_user_id,
        )

    async def _populate_profiles_full_user_id(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """Populates the `profiles.full_user_id` column.

        In a future Synapse version, this column will be renamed to `user_id`, replacing
        the existing `user_id` column.

        Note that completion of this background update does not imply that there are no
        longer any `NULL` values in `full_user_id`. Until the old `user_id` column has
        been removed, Synapse may be rolled back to a previous version which does not
        populate `full_user_id` after the background update has finished.
        """

        def _populate_profiles_full_user_id_txn(
            txn: LoggingTransaction,
        ) -> bool:
            sql = """
                UPDATE profiles
                SET full_user_id = '@' || user_id || ':' || ?
                WHERE user_id IN (
                    SELECT user_id
                    FROM profiles
                    WHERE full_user_id IS NULL
                    LIMIT ?
                )
            """
            txn.execute(sql, (self.hs.hostname, batch_size))

            return txn.rowcount == 0

        finished = await self.db_pool.runInteraction(
            "_populate_profiles_full_user_id_txn",
            _populate_profiles_full_user_id_txn,
        )

        if finished:
            await self.db_pool.updates._end_background_update(
                self.POPULATE_PROFILES_FULL_USER_ID
            )

        return batch_size


class ProfileStore(ProfileBackgroundUpdateStore):
    pass

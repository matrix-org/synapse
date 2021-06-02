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
from typing import Any, Dict, List, Optional

from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.databases.main.roommember import ProfileInfo


class ProfileWorkerStore(SQLBaseStore):
    async def get_profileinfo(self, user_localpart: str) -> ProfileInfo:
        try:
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

    async def get_profile_displayname(self, user_localpart: str) -> Optional[str]:
        return await self.db_pool.simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    async def get_profile_avatar_url(self, user_localpart: str) -> Optional[str]:
        return await self.db_pool.simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    async def get_from_remote_profile_cache(
        self, user_id: str
    ) -> Optional[Dict[str, Any]]:
        return await self.db_pool.simple_select_one(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            retcols=("displayname", "avatar_url"),
            allow_none=True,
            desc="get_from_remote_profile_cache",
        )

    async def create_profile(self, user_localpart: str) -> None:
        await self.db_pool.simple_insert(
            table="profiles", values={"user_id": user_localpart}, desc="create_profile"
        )

    async def set_profile_displayname(
        self, user_localpart: str, new_displayname: Optional[str]
    ) -> None:
        await self.db_pool.simple_update_one(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            updatevalues={"displayname": new_displayname},
            desc="set_profile_displayname",
        )

    async def set_profile_avatar_url(
        self, user_localpart: str, new_avatar_url: Optional[str]
    ) -> None:
        await self.db_pool.simple_update_one(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            updatevalues={"avatar_url": new_avatar_url},
            desc="set_profile_avatar_url",
        )

    async def update_remote_profile_cache(
        self, user_id: str, displayname: str, avatar_url: str
    ) -> int:
        return await self.db_pool.simple_update(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            updatevalues={
                "displayname": displayname,
                "avatar_url": avatar_url,
                "last_check": self._clock.time_msec(),
            },
            desc="update_remote_profile_cache",
        )

    async def maybe_delete_remote_profile_cache(self, user_id):
        """Check if we still care about the remote user's profile, and if we
        don't then remove their profile from the cache
        """
        subscribed = await self.is_subscribed_remote_profile_for_user(user_id)
        if not subscribed:
            await self.db_pool.simple_delete(
                table="remote_profile_cache",
                keyvalues={"user_id": user_id},
                desc="delete_remote_profile_cache",
            )

    async def is_subscribed_remote_profile_for_user(self, user_id):
        """Check whether we are interested in a remote user's profile."""
        res = await self.db_pool.simple_select_one_onecol(
            table="group_users",
            keyvalues={"user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="should_update_remote_profile_cache_for_user",
        )

        if res:
            return True

        res = await self.db_pool.simple_select_one_onecol(
            table="group_invites",
            keyvalues={"user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="should_update_remote_profile_cache_for_user",
        )

        if res:
            return True

    async def get_remote_profile_cache_entries_that_expire(
        self, last_checked: int
    ) -> List[Dict[str, str]]:
        """Get all users who haven't been checked since `last_checked`"""

        def _get_remote_profile_cache_entries_that_expire_txn(txn):
            sql = """
                SELECT user_id, displayname, avatar_url
                FROM remote_profile_cache
                WHERE last_check < ?
            """

            txn.execute(sql, (last_checked,))

            return self.db_pool.cursor_to_dict(txn)

        return await self.db_pool.runInteraction(
            "get_remote_profile_cache_entries_that_expire",
            _get_remote_profile_cache_entries_that_expire_txn,
        )


class ProfileStore(ProfileWorkerStore):
    async def add_remote_profile_cache(
        self, user_id: str, displayname: str, avatar_url: str
    ) -> None:
        """Ensure we are caching the remote user's profiles.

        This should only be called when `is_subscribed_remote_profile_for_user`
        would return true for the user.
        """
        await self.db_pool.simple_upsert(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            values={
                "displayname": displayname,
                "avatar_url": avatar_url,
                "last_check": self._clock.time_msec(),
            },
            desc="add_remote_profile_cache",
        )

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
from typing import Any, Dict, List, Optional, Tuple

from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import LoggingTransaction
from synapse.storage.databases.main.roommember import ProfileInfo
from synapse.types import UserID
from synapse.util.caches.descriptors import cached

BATCH_SIZE = 100


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

    @cached(max_entries=5000)
    async def get_profile_displayname(self, user_localpart: str) -> Optional[str]:
        return await self.db_pool.simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    @cached(max_entries=5000)
    async def get_profile_avatar_url(self, user_localpart: str) -> Optional[str]:
        return await self.db_pool.simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    async def get_latest_profile_replication_batch_number(self) -> Optional[int]:
        def f(txn: LoggingTransaction) -> Optional[int]:
            txn.execute("SELECT MAX(batch) as maxbatch FROM profiles")
            rows = self.db_pool.cursor_to_dict(txn)
            return rows[0]["maxbatch"]

        return await self.db_pool.runInteraction(
            "get_latest_profile_replication_batch_number", f
        )

    async def get_profile_batch(self, batchnum: int) -> List[Dict[str, Any]]:
        return await self.db_pool.simple_select_list(
            table="profiles",
            keyvalues={"batch": batchnum},
            retcols=("user_id", "displayname", "avatar_url", "active"),
            desc="get_profile_batch",
        )

    async def assign_profile_batch(self) -> int:
        def f(txn: LoggingTransaction) -> int:
            sql = (
                "UPDATE profiles SET batch = "
                "(SELECT COALESCE(MAX(batch), -1) + 1 FROM profiles) "
                "WHERE user_id in ("
                "    SELECT user_id FROM profiles WHERE batch is NULL limit ?"
                ")"
            )
            txn.execute(sql, (BATCH_SIZE,))
            return txn.rowcount

        return await self.db_pool.runInteraction("assign_profile_batch", f)

    async def get_replication_hosts(self) -> Dict[str, int]:
        def f(txn: LoggingTransaction) -> Dict[str, int]:
            txn.execute(
                "SELECT host, last_synced_batch FROM profile_replication_status"
            )
            rows = self.db_pool.cursor_to_dict(txn)
            return {r["host"]: r["last_synced_batch"] for r in rows}

        return await self.db_pool.runInteraction("get_replication_hosts", f)

    async def update_replication_batch_for_host(
        self, host: str, last_synced_batch: int
    ) -> bool:
        return await self.db_pool.simple_upsert(
            table="profile_replication_status",
            keyvalues={"host": host},
            values={"last_synced_batch": last_synced_batch},
            desc="update_replication_batch_for_host",
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
        self,
        user_localpart: str,
        new_displayname: Optional[str],
        batchnum: Optional[int],
    ) -> None:
        # Invalidate the read cache for this user
        self.get_profile_displayname.invalidate((user_localpart,))

        await self.db_pool.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"displayname": new_displayname, "batch": batchnum},
            desc="set_profile_displayname",
            lock=False,  # we can do this because user_id has a unique index
        )

    async def set_profile_avatar_url(
        self,
        user_localpart: str,
        new_avatar_url: Optional[str],
        batchnum: Optional[int],
    ) -> None:
        # Invalidate the read cache for this user
        self.get_profile_avatar_url.invalidate((user_localpart,))

        await self.db_pool.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"avatar_url": new_avatar_url, "batch": batchnum},
            desc="set_profile_avatar_url",
            lock=False,  # we can do this because user_id has a unique index
        )

    async def set_profiles_active(
        self,
        users: List[UserID],
        active: bool,
        hide: bool,
        batchnum: Optional[int],
    ) -> None:
        """Given a set of users, set active and hidden flags on them.

        Args:
            users: A list of UserIDs
            active: Whether to set the users to active or inactive
            hide: Whether to hide the users (withold from replication). If
                False and active is False, users will have their profiles
                erased
            batchnum: The batch number, used for profile replication
        """
        # Convert list of localparts to list of tuples containing localparts
        user_localparts = [(user.localpart,) for user in users]

        # Generate list of value tuples for each user
        value_names = ["active", "batch"]
        values = [(int(active), batchnum) for _ in user_localparts]  # type: List[Tuple]

        if not active and not hide:
            # we are deactivating for real (not in hide mode)
            # so clear the profile information
            value_names += ["avatar_url", "displayname"]
            values = [v + (None, None) for v in values]

        return await self.db_pool.runInteraction(
            "set_profiles_active",
            self.db_pool.simple_upsert_many_txn,
            table="profiles",
            key_names=("user_id",),
            key_values=user_localparts,
            value_names=value_names,
            value_values=values,
        )

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

    async def update_remote_profile_cache(
        self, user_id: str, displayname: Optional[str], avatar_url: Optional[str]
    ) -> int:
        return await self.db_pool.simple_upsert(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            values={
                "displayname": displayname,
                "avatar_url": avatar_url,
                "last_check": self._clock.time_msec(),
            },
            desc="update_remote_profile_cache",
        )

    async def maybe_delete_remote_profile_cache(self, user_id: str) -> None:
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

    async def is_subscribed_remote_profile_for_user(self, user_id: str) -> bool:
        """Check whether we are interested in a remote user's profile."""
        res: Optional[str] = await self.db_pool.simple_select_one_onecol(
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
        return False

    async def get_remote_profile_cache_entries_that_expire(
        self, last_checked: int
    ) -> List[Dict[str, str]]:
        """Get all users who haven't been checked since `last_checked`"""

        def _get_remote_profile_cache_entries_that_expire_txn(
            txn: LoggingTransaction,
        ) -> List[Dict[str, str]]:
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

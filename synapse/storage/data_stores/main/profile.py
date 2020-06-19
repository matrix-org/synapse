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

from typing import List, Tuple

from twisted.internet import defer

from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.data_stores.main.roommember import ProfileInfo
from synapse.types import UserID
from synapse.util.caches.descriptors import cached

BATCH_SIZE = 100


class ProfileWorkerStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_profileinfo(self, user_localpart):
        try:
            profile = yield self.db.simple_select_one(
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
    def get_profile_displayname(self, user_localpart):
        return self.db.simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    @cached(max_entries=5000)
    def get_profile_avatar_url(self, user_localpart):
        return self.db.simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    def get_latest_profile_replication_batch_number(self):
        def f(txn):
            txn.execute("SELECT MAX(batch) as maxbatch FROM profiles")
            rows = self.db.cursor_to_dict(txn)
            return rows[0]["maxbatch"]

        return self.db.runInteraction("get_latest_profile_replication_batch_number", f)

    def get_profile_batch(self, batchnum):
        return self.db.simple_select_list(
            table="profiles",
            keyvalues={"batch": batchnum},
            retcols=("user_id", "displayname", "avatar_url", "active"),
            desc="get_profile_batch",
        )

    def assign_profile_batch(self):
        def f(txn):
            sql = (
                "UPDATE profiles SET batch = "
                "(SELECT COALESCE(MAX(batch), -1) + 1 FROM profiles) "
                "WHERE user_id in ("
                "    SELECT user_id FROM profiles WHERE batch is NULL limit ?"
                ")"
            )
            txn.execute(sql, (BATCH_SIZE,))
            return txn.rowcount

        return self.db.runInteraction("assign_profile_batch", f)

    def get_replication_hosts(self):
        def f(txn):
            txn.execute(
                "SELECT host, last_synced_batch FROM profile_replication_status"
            )
            rows = self.db.cursor_to_dict(txn)
            return {r["host"]: r["last_synced_batch"] for r in rows}

        return self.db.runInteraction("get_replication_hosts", f)

    def update_replication_batch_for_host(self, host, last_synced_batch):
        return self.db.simple_upsert(
            table="profile_replication_status",
            keyvalues={"host": host},
            values={"last_synced_batch": last_synced_batch},
            desc="update_replication_batch_for_host",
        )

    def get_from_remote_profile_cache(self, user_id):
        return self.db.simple_select_one(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            retcols=("displayname", "avatar_url"),
            allow_none=True,
            desc="get_from_remote_profile_cache",
        )

    def create_profile(self, user_localpart):
        return self.db.simple_insert(
            table="profiles", values={"user_id": user_localpart}, desc="create_profile"
        )

    def set_profile_displayname(self, user_localpart, new_displayname, batchnum):
        # Invalidate the read cache for this user
        self.get_profile_displayname.invalidate((user_localpart,))

        return self.db.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"displayname": new_displayname, "batch": batchnum},
            desc="set_profile_displayname",
            lock=False,  # we can do this because user_id has a unique index
        )

    def set_profile_avatar_url(self, user_localpart, new_avatar_url, batchnum):
        # Invalidate the read cache for this user
        self.get_profile_avatar_url.invalidate((user_localpart,))

        return self.db.simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={"avatar_url": new_avatar_url, "batch": batchnum},
            desc="set_profile_avatar_url",
            lock=False,  # we can do this because user_id has a unique index
        )

    def set_profiles_active(
        self, users: List[UserID], active: bool, hide: bool, batchnum: int,
    ):
        """Given a set of users, set active and hidden flags on them.

        Args:
            users: A list of UserIDs
            active: Whether to set the users to active or inactive
            hide: Whether to hide the users (withold from replication). If
                False and active is False, users will have their profiles
                erased
            batchnum: The batch number, used for profile replication

        Returns:
            Deferred
        """
        # Convert list of localparts to list of tuples containing localparts
        user_localparts = [(user.localpart,) for user in users]

        # Generate list of value tuples for each user
        value_names = ("active", "batch")
        values = [(int(active), batchnum) for _ in user_localparts]  # type: List[Tuple]

        if not active and not hide:
            # we are deactivating for real (not in hide mode)
            # so clear the profile information
            value_names += ("avatar_url", "displayname")
            values = [v + (None, None) for v in values]

        return self.db.runInteraction(
            "set_profiles_active",
            self.db.simple_upsert_many_txn,
            table="profiles",
            key_names=("user_id",),
            key_values=user_localparts,
            value_names=value_names,
            value_values=values,
        )


class ProfileStore(ProfileWorkerStore):
    def __init__(self, database, db_conn, hs):

        super(ProfileStore, self).__init__(database, db_conn, hs)

        self.db.updates.register_background_index_update(
            "profile_replication_status_host_index",
            index_name="profile_replication_status_idx",
            table="profile_replication_status",
            columns=["host"],
            unique=True,
        )

    def add_remote_profile_cache(self, user_id, displayname, avatar_url):
        """Ensure we are caching the remote user's profiles.

        This should only be called when `is_subscribed_remote_profile_for_user`
        would return true for the user.
        """
        return self.db.simple_upsert(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            values={
                "displayname": displayname,
                "avatar_url": avatar_url,
                "last_check": self._clock.time_msec(),
            },
            desc="add_remote_profile_cache",
        )

    def update_remote_profile_cache(self, user_id, displayname, avatar_url):
        return self.db.simple_upsert(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            updatevalues={
                "displayname": displayname,
                "avatar_url": avatar_url,
                "last_check": self._clock.time_msec(),
            },
            desc="update_remote_profile_cache",
        )

    @defer.inlineCallbacks
    def maybe_delete_remote_profile_cache(self, user_id):
        """Check if we still care about the remote user's profile, and if we
        don't then remove their profile from the cache
        """
        subscribed = yield self.is_subscribed_remote_profile_for_user(user_id)
        if not subscribed:
            yield self.db.simple_delete(
                table="remote_profile_cache",
                keyvalues={"user_id": user_id},
                desc="delete_remote_profile_cache",
            )

    def get_remote_profile_cache_entries_that_expire(self, last_checked):
        """Get all users who haven't been checked since `last_checked`
        """

        def _get_remote_profile_cache_entries_that_expire_txn(txn):
            sql = """
                SELECT user_id, displayname, avatar_url
                FROM remote_profile_cache
                WHERE last_check < ?
            """

            txn.execute(sql, (last_checked,))

            return self.db.cursor_to_dict(txn)

        return self.db.runInteraction(
            "get_remote_profile_cache_entries_that_expire",
            _get_remote_profile_cache_entries_that_expire_txn,
        )

    @defer.inlineCallbacks
    def is_subscribed_remote_profile_for_user(self, user_id):
        """Check whether we are interested in a remote user's profile.
        """
        res = yield self.db.simple_select_one_onecol(
            table="group_users",
            keyvalues={"user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="should_update_remote_profile_cache_for_user",
        )

        if res:
            return True

        res = yield self.db.simple_select_one_onecol(
            table="group_invites",
            keyvalues={"user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="should_update_remote_profile_cache_for_user",
        )

        if res:
            return True

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

from twisted.internet import defer

from synapse.api.errors import StoreError
from synapse.storage.roommember import ProfileInfo

from . import background_updates
from ._base import SQLBaseStore

BATCH_SIZE = 100


class ProfileWorkerStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_profileinfo(self, user_localpart):
        try:
            profile = yield self._simple_select_one(
                table="profiles",
                keyvalues={"user_id": user_localpart},
                retcols=("displayname", "avatar_url"),
                desc="get_profileinfo",
            )
        except StoreError as e:
            if e.code == 404:
                # no match
                defer.returnValue(ProfileInfo(None, None))
                return
            else:
                raise

        defer.returnValue(
            ProfileInfo(
                avatar_url=profile['avatar_url'], display_name=profile['displayname']
            )
        )

    def get_profile_displayname(self, user_localpart):
        return self._simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    def get_profile_avatar_url(self, user_localpart):
        return self._simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    def get_latest_profile_replication_batch_number(self):
        def f(txn):
            txn.execute("SELECT MAX(batch) as maxbatch FROM profiles")
            rows = self.cursor_to_dict(txn)
            return rows[0]['maxbatch']
        return self.runInteraction(
            "get_latest_profile_replication_batch_number", f,
        )

    def get_profile_batch(self, batchnum):
        return self._simple_select_list(
            table="profiles",
            keyvalues={
                "batch": batchnum,
            },
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
        return self.runInteraction("assign_profile_batch", f)

    def get_replication_hosts(self):
        def f(txn):
            txn.execute("SELECT host, last_synced_batch FROM profile_replication_status")
            rows = self.cursor_to_dict(txn)
            return {r['host']: r['last_synced_batch'] for r in rows}
        return self.runInteraction("get_replication_hosts", f)

    def update_replication_batch_for_host(self, host, last_synced_batch):
        return self._simple_upsert(
            table="profile_replication_status",
            keyvalues={"host": host},
            values={
                "last_synced_batch": last_synced_batch,
            },
            desc="update_replication_batch_for_host",
        )

    def get_from_remote_profile_cache(self, user_id):
        return self._simple_select_one(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            retcols=("displayname", "avatar_url"),
            allow_none=True,
            desc="get_from_remote_profile_cache",
        )

    def set_profile_displayname(self, user_localpart, new_displayname, batchnum):
        return self._simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={
                "displayname": new_displayname,
                "batch": batchnum,
            },
            desc="set_profile_displayname",
            lock=False  # we can do this because user_id has a unique index
        )

    def set_profile_avatar_url(self, user_localpart, new_avatar_url, batchnum):
        return self._simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values={
                "avatar_url": new_avatar_url,
                "batch": batchnum,
            },
            desc="set_profile_avatar_url",
            lock=False  # we can do this because user_id has a unique index
        )

    def set_profile_active(self, user_localpart, active, hide, batchnum):
        values = {
            "active": int(active),
            "batch": batchnum,
        }
        if not active and not hide:
            # we are deactivating for real (not in hide mode)
            # so clear the profile.
            values["avatar_url"] = None
            values["displayname"] = None
        return self._simple_upsert(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            values=values,
            desc="set_profile_active",
            lock=False  # we can do this because user_id has a unique index
        )


class ProfileStore(ProfileWorkerStore, background_updates.BackgroundUpdateStore):
    def __init__(self, db_conn, hs):

        super(ProfileStore, self).__init__(db_conn, hs)

        self.register_background_index_update(
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
        return self._simple_upsert(
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
        return self._simple_update(
            table="remote_profile_cache",
            keyvalues={"user_id": user_id},
            values={
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
            yield self._simple_delete(
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

            return self.cursor_to_dict(txn)

        return self.runInteraction(
            "get_remote_profile_cache_entries_that_expire",
            _get_remote_profile_cache_entries_that_expire_txn,
        )

    @defer.inlineCallbacks
    def is_subscribed_remote_profile_for_user(self, user_id):
        """Check whether we are interested in a remote user's profile.
        """
        res = yield self._simple_select_one_onecol(
            table="group_users",
            keyvalues={"user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="should_update_remote_profile_cache_for_user",
        )

        if res:
            defer.returnValue(True)

        res = yield self._simple_select_one_onecol(
            table="group_invites",
            keyvalues={"user_id": user_id},
            retcol="user_id",
            allow_none=True,
            desc="should_update_remote_profile_cache_for_user",
        )

        if res:
            defer.returnValue(True)

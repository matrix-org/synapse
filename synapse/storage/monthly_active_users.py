# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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

from synapse.util.caches.descriptors import cached, cachedInlineCallbacks

from ._base import SQLBaseStore


class MonthlyActiveUsersStore(SQLBaseStore):
    def __init__(self, dbconn, hs):
        super(MonthlyActiveUsersStore, self).__init__(None, hs)
        self._clock = hs.get_clock()
        self.hs = hs

    def reap_monthly_active_users(self):
        """
        Cleans out monthly active user table to ensure that no stale
        entries exist.
        Return:
            Defered()
        """
        def _reap_users(txn):

            thirty_days_ago = (
                int(self._clock.time_msec()) - (1000 * 60 * 60 * 24 * 30)
            )

            sql = "DELETE FROM monthly_active_users WHERE timestamp < ?"

            txn.execute(sql, (thirty_days_ago,))
            sql = """
                DELETE FROM monthly_active_users
                ORDER BY timestamp desc
                LIMIT -1 OFFSET ?
                """
            txn.execute(sql, (self.hs.config.max_mau_value,))

        res = self.runInteraction("reap_monthly_active_users", _reap_users)
        # It seems poor to invalidate the whole cache, Postgres supports
        # 'Returning' which would allow me to invalidate only the
        # specific users, but sqlite has no way to do this and instead
        # I would need to SELECT and the DELETE which without locking
        # is racy.
        # Have resolved to invalidate the whole cache for now and do
        # something about it if and when the perf becomes significant
        self.is_user_monthly_active.invalidate_all()
        self.get_monthly_active_count.invalidate_all()
        return res

    @cached(num_args=0)
    def get_monthly_active_count(self):
        """
            Generates current count of monthly active users.abs
            Return:
                Defered(int): Number of current monthly active users
        """

        def _count_users(txn):
            sql = "SELECT COALESCE(count(*), 0) FROM monthly_active_users"

            txn.execute(sql)
            count, = txn.fetchone()
            return count
        return self.runInteraction("count_users", _count_users)

    def upsert_monthly_active_user(self, user_id):
        """
            Updates or inserts monthly active user member
            Arguments:
                user_id (str): user to add/update
            Deferred(bool): True if a new entry was created, False if an
                existing one was updated.
        """
        self._simple_upsert(
            desc="upsert_monthly_active_user",
            table="monthly_active_users",
            keyvalues={
                "user_id": user_id,
            },
            values={
                "timestamp": int(self._clock.time_msec()),
            },
            lock=False,
        )
        self.is_user_monthly_active.invalidate((user_id,))
        self.get_monthly_active_count.invalidate(())

    @cachedInlineCallbacks(num_args=1)
    def is_user_monthly_active(self, user_id):
        """
            Checks if a given user is part of the monthly active user group
            Arguments:
                user_id (str): user to add/update
            Return:
                bool : True if user part of group, False otherwise
        """
        user_present = yield self._simple_select_onecol(
            table="monthly_active_users",
            keyvalues={
                "user_id": user_id,
            },
            retcol="user_id",
            desc="is_user_monthly_active",
        )
        defer.returnValue(bool(user_present))

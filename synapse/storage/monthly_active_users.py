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
import logging

from twisted.internet import defer

from synapse.util.caches.descriptors import cached

from ._base import SQLBaseStore

logger = logging.getLogger(__name__)

# Number of msec of granularity to store the monthly_active_user timestamp
# This means it is not necessary to update the table on every request
LAST_SEEN_GRANULARITY = 60 * 60 * 1000


class MonthlyActiveUsersStore(SQLBaseStore):
    def __init__(self, dbconn, hs):
        super(MonthlyActiveUsersStore, self).__init__(None, hs)
        self._clock = hs.get_clock()
        self.hs = hs
        self.reserved_users = ()

    @defer.inlineCallbacks
    def initialise_reserved_users(self, threepids):
        store = self.hs.get_datastore()
        reserved_user_list = []

        # Do not add more reserved users than the total allowable number
        for tp in threepids[:self.hs.config.max_mau_value]:
            user_id = yield store.get_user_id_by_threepid(
                tp["medium"], tp["address"]
            )
            if user_id:
                yield self.upsert_monthly_active_user(user_id)
                reserved_user_list.append(user_id)
            else:
                logger.warning(
                    "mau limit reserved threepid %s not found in db" % tp
                )
        self.reserved_users = tuple(reserved_user_list)

    @defer.inlineCallbacks
    def reap_monthly_active_users(self):
        """
        Cleans out monthly active user table to ensure that no stale
        entries exist.

        Returns:
            Deferred[]
        """
        def _reap_users(txn):
            # Purge stale users

            thirty_days_ago = (
                int(self._clock.time_msec()) - (1000 * 60 * 60 * 24 * 30)
            )
            query_args = [thirty_days_ago]
            base_sql = "DELETE FROM monthly_active_users WHERE timestamp < ?"

            # Need if/else since 'AND user_id NOT IN ({})' fails on Postgres
            # when len(reserved_users) == 0. Works fine on sqlite.
            if len(self.reserved_users) > 0:
                # questionmarks is a hack to overcome sqlite not supporting
                # tuples in 'WHERE IN %s'
                questionmarks = '?' * len(self.reserved_users)

                query_args.extend(self.reserved_users)
                sql = base_sql + """ AND user_id NOT IN ({})""".format(
                    ','.join(questionmarks)
                )
            else:
                sql = base_sql

            txn.execute(sql, query_args)

            # If MAU user count still exceeds the MAU threshold, then delete on
            # a least recently active basis.
            # Note it is not possible to write this query using OFFSET due to
            # incompatibilities in how sqlite and postgres support the feature.
            # sqlite requires 'LIMIT -1 OFFSET ?', the LIMIT must be present
            # While Postgres does not require 'LIMIT', but also does not support
            # negative LIMIT values. So there is no way to write it that both can
            # support
            safe_guard = self.hs.config.max_mau_value - len(self.reserved_users)
            # Must be greater than zero for postgres
            safe_guard = safe_guard if safe_guard > 0 else 0
            query_args = [safe_guard]

            base_sql = """
                DELETE FROM monthly_active_users
                WHERE user_id NOT IN (
                    SELECT user_id FROM monthly_active_users
                    ORDER BY timestamp DESC
                    LIMIT ?
                    )
                """
            # Need if/else since 'AND user_id NOT IN ({})' fails on Postgres
            # when len(reserved_users) == 0. Works fine on sqlite.
            if len(self.reserved_users) > 0:
                query_args.extend(self.reserved_users)
                sql = base_sql + """ AND user_id NOT IN ({})""".format(
                    ','.join(questionmarks)
                )
            else:
                sql = base_sql
            txn.execute(sql, query_args)

        yield self.runInteraction("reap_monthly_active_users", _reap_users)
        # It seems poor to invalidate the whole cache, Postgres supports
        # 'Returning' which would allow me to invalidate only the
        # specific users, but sqlite has no way to do this and instead
        # I would need to SELECT and the DELETE which without locking
        # is racy.
        # Have resolved to invalidate the whole cache for now and do
        # something about it if and when the perf becomes significant
        self.user_last_seen_monthly_active.invalidate_all()
        self.get_monthly_active_count.invalidate_all()

    @cached(num_args=0)
    def get_monthly_active_count(self):
        """Generates current count of monthly active users

        Returns:
            Defered[int]: Number of current monthly active users
        """

        def _count_users(txn):
            sql = "SELECT COALESCE(count(*), 0) FROM monthly_active_users"

            txn.execute(sql)
            count, = txn.fetchone()
            return count
        return self.runInteraction("count_users", _count_users)

    @defer.inlineCallbacks
    def get_registered_reserved_users_count(self):
        """Of the reserved threepids defined in config, how many are associated
        with registered users?

        Returns:
            Defered[int]: Number of real reserved users
        """
        count = 0
        for tp in self.hs.config.mau_limits_reserved_threepids:
            user_id = yield self.hs.get_datastore().get_user_id_by_threepid(
                tp["medium"], tp["address"]
            )
            if user_id:
                count = count + 1
        defer.returnValue(count)

    @defer.inlineCallbacks
    def upsert_monthly_active_user(self, user_id):
        """
            Updates or inserts monthly active user member
            Arguments:
                user_id (str): user to add/update
            Deferred[bool]: True if a new entry was created, False if an
                existing one was updated.
        """
        # Am consciously deciding to lock the table on the basis that is ought
        # never be a big table and alternative approaches (batching multiple
        # upserts into a single txn) introduced a lot of extra complexity.
        # See https://github.com/matrix-org/synapse/issues/3854 for more
        is_insert = yield self._simple_upsert(
            desc="upsert_monthly_active_user",
            table="monthly_active_users",
            keyvalues={
                "user_id": user_id,
            },
            values={
                "timestamp": int(self._clock.time_msec()),
            },
        )
        if is_insert:
            self.user_last_seen_monthly_active.invalidate((user_id,))
            self.get_monthly_active_count.invalidate(())

    @cached(num_args=1)
    def user_last_seen_monthly_active(self, user_id):
        """
            Checks if a given user is part of the monthly active user group
            Arguments:
                user_id (str): user to add/update
            Return:
                Deferred[int] : timestamp since last seen, None if never seen

        """

        return(self._simple_select_one_onecol(
            table="monthly_active_users",
            keyvalues={
                "user_id": user_id,
            },
            retcol="timestamp",
            allow_none=True,
            desc="user_last_seen_monthly_active",
        ))

    @defer.inlineCallbacks
    def populate_monthly_active_users(self, user_id):
        """Checks on the state of monthly active user limits and optionally
        add the user to the monthly active tables

        Args:
            user_id(str): the user_id to query
        """

        if self.hs.config.limit_usage_by_mau:
            # Trial users and guests should not be included as part of MAU group
            is_guest = yield self.is_guest(user_id)
            if is_guest:
                return
            is_trial = yield self.is_trial_user(user_id)
            if is_trial:
                return

            last_seen_timestamp = yield self.user_last_seen_monthly_active(user_id)
            now = self.hs.get_clock().time_msec()

            # We want to reduce to the total number of db writes, and are happy
            # to trade accuracy of timestamp in order to lighten load. This means
            # We always insert new users (where MAU threshold has not been reached),
            # but only update if we have not previously seen the user for
            # LAST_SEEN_GRANULARITY ms
            if last_seen_timestamp is None:
                count = yield self.get_monthly_active_count()
                if count < self.hs.config.max_mau_value:
                    yield self.upsert_monthly_active_user(user_id)
            elif now - last_seen_timestamp > LAST_SEEN_GRANULARITY:
                yield self.upsert_monthly_active_user(user_id)

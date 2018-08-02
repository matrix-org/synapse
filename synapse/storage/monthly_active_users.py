from twisted.internet import defer
from synapse.util.caches.descriptors import cachedInlineCallbacks
from synapse.storage.engines import PostgresEngine, Sqlite3Engine

from ._base import SQLBaseStore


class MonthlyActiveUsersStore(SQLBaseStore):
    def __init__(self, dbconn, hs):
        super(MonthlyActiveUsersStore, self).__init__(None, hs)
        self._clock = hs.get_clock()
        self.max_mau_value = hs.config.max_mau_value

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

            if isinstance(self.database_engine, PostgresEngine):
                sql = """
                    DELETE FROM monthly_active_users
                    WHERE timestamp < ?
                    RETURNING user_id
                    """
                txn.execute(sql, (thirty_days_ago,))
                res = txn.fetchall()
                for r in res:
                    self.is_user_monthly_active.invalidate(r)

                sql = """
                    DELETE FROM monthly_active_users
                    ORDER BY timestamp desc
                    LIMIT -1 OFFSET ?
                    RETURNING user_id
                    """
                txn.execute(sql, (self.max_mau_value,))
                res = txn.fetchall()
                for r in res:
                    self.is_user_monthly_active.invalidate(r)
                    print r
                self.get_monthly_active_count.invalidate()
            elif isinstance(self.database_engine, Sqlite3Engine):
                sql = "DELETE FROM monthly_active_users WHERE timestamp < ?"

                txn.execute(sql, (thirty_days_ago,))
                sql = """
                    DELETE FROM monthly_active_users
                    ORDER BY timestamp desc
                    LIMIT -1 OFFSET ?
                    """
                txn.execute(sql, (self.max_mau_value,))

                # It seems poor to invalidate the whole cache, but the alternative
                # is to select then delete which has its own problems.
                # It seems unlikely that anyone using this feature on large datasets
                # would be using sqlite and if they are then there will be
                # larger perf issues than this one to encourage an upgrade to postgres.

                self.is_user_monthly_active.invalidate_all()
                self.get_monthly_active_count.invalidate_all()

        return self.runInteraction("reap_monthly_active_users", _reap_users)

    @cachedInlineCallbacks(num_args=0)
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
        return self._simple_upsert(
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

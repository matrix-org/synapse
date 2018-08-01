from twisted.internet import defer

from ._base import SQLBaseStore


class MonthlyActiveUsersStore(SQLBaseStore):
    def __init__(self, hs):
        super(MonthlyActiveUsersStore, self).__init__(None, hs)
        self._clock = hs.get_clock()
        self.max_mau_value = hs.config.max_mau_value

    def reap_monthly_active_users(self):
        """
        Cleans out monthly active user table to ensure that no stale
        entries exist.
        Return:
            defered, no return type
        """
        def _reap_users(txn):
            thirty_days_ago = (
                int(self._clock.time_msec()) - (1000 * 60 * 60 * 24 * 30)
            )

            # Query deletes the union of users that have either:
            #     * not visited in the last 30 days
            #     * exceeded the total max_mau_value threshold. Where there is
            #       an excess, more recent users are favoured - this is to cover
            #       the case where the limit has been step change reduced.
            #
            sql = """
            DELETE FROM monthly_active_users
            WHERE user_id
            IN (
                SELECT * FROM (
                    SELECT monthly_active_users.user_id
                    FROM monthly_active_users
                    LEFT JOIN (
                        SELECT user_id, max(last_seen) AS last_seen
                        FROM user_ips
                        GROUP BY user_id
                    ) AS uip ON uip.user_id=monthly_active_users.user_id
                    ORDER BY uip.last_seen desc LIMIT -1 OFFSET ?
                )
                UNION
                SELECT * FROM (
                    SELECT monthly_active_users.user_id
                    FROM monthly_active_users
                    LEFT JOIN (
                        SELECT user_id, max(last_seen) AS last_seen
                        FROM user_ips
                        GROUP BY user_id
                    ) AS uip  ON uip.user_id=monthly_active_users.user_id
                    WHERE uip.last_seen < ?
                )
            )
            """

            txn.execute(sql, (self.max_mau_value, thirty_days_ago,))

        return self.runInteraction("reap_monthly_active_users", _reap_users)

    def get_monthly_active_count(self):
        """
            Generates current count of monthly active users.abs
            return:
                defered resolves to int
        """
        def _count_users(txn):
            sql = "SELECT COALESCE(count(*), 0) FROM monthly_active_users"

            txn.execute(sql)
            count, = txn.fetchone()
            return count
        return self.runInteraction("count_users", _count_users)

    def insert_monthly_active_user(self, user_id):
        """
            Updates or inserts monthly active user member
            Arguments:
                user_id (str): user to add/update
        """
        return self._simple_insert(
            desc="insert_monthly_active_user",
            table="monthly_active_users",
            values={
                "user_id": user_id,
            },
        )

    @defer.inlineCallbacks
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

# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import calendar
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from synapse.api.constants import PresenceState
from synapse.config.homeserver import HomeServerConfig
from synapse.storage.database import DatabasePool
from synapse.storage.engines import PostgresEngine
from synapse.storage.util.id_generators import (
    IdGenerator,
    MultiWriterIdGenerator,
    StreamIdGenerator,
)
from synapse.types import get_domain_from_id
from synapse.util.caches.stream_change_cache import StreamChangeCache

from .account_data import AccountDataStore
from .appservice import ApplicationServiceStore, ApplicationServiceTransactionStore
from .cache import CacheInvalidationWorkerStore
from .censor_events import CensorEventsStore
from .client_ips import ClientIpStore
from .deviceinbox import DeviceInboxStore
from .devices import DeviceStore
from .directory import DirectoryStore
from .e2e_room_keys import EndToEndRoomKeyStore
from .end_to_end_keys import EndToEndKeyStore
from .event_federation import EventFederationStore
from .event_push_actions import EventPushActionsStore
from .events_bg_updates import EventsBackgroundUpdatesStore
from .filtering import FilteringStore
from .group_server import GroupServerStore
from .keys import KeyStore
from .media_repository import MediaRepositoryStore
from .metrics import ServerMetricsStore
from .monthly_active_users import MonthlyActiveUsersStore
from .openid import OpenIdStore
from .presence import PresenceStore, UserPresenceState
from .profile import ProfileStore
from .purge_events import PurgeEventsStore
from .push_rule import PushRuleStore
from .pusher import PusherStore
from .receipts import ReceiptsStore
from .registration import RegistrationStore
from .rejections import RejectionsStore
from .relations import RelationsStore
from .room import RoomStore
from .roommember import RoomMemberStore
from .search import SearchStore
from .signatures import SignatureStore
from .state import StateStore
from .stats import StatsStore
from .stream import StreamStore
from .tags import TagsStore
from .transactions import TransactionStore
from .ui_auth import UIAuthStore
from .user_directory import UserDirectoryStore
from .user_erasure_store import UserErasureStore

logger = logging.getLogger(__name__)


class DataStore(
    EventsBackgroundUpdatesStore,
    RoomMemberStore,
    RoomStore,
    RegistrationStore,
    StreamStore,
    ProfileStore,
    PresenceStore,
    TransactionStore,
    DirectoryStore,
    KeyStore,
    StateStore,
    SignatureStore,
    ApplicationServiceStore,
    PurgeEventsStore,
    EventFederationStore,
    MediaRepositoryStore,
    RejectionsStore,
    FilteringStore,
    PusherStore,
    PushRuleStore,
    ApplicationServiceTransactionStore,
    ReceiptsStore,
    EndToEndKeyStore,
    EndToEndRoomKeyStore,
    SearchStore,
    TagsStore,
    AccountDataStore,
    EventPushActionsStore,
    OpenIdStore,
    ClientIpStore,
    DeviceStore,
    DeviceInboxStore,
    UserDirectoryStore,
    GroupServerStore,
    UserErasureStore,
    MonthlyActiveUsersStore,
    StatsStore,
    RelationsStore,
    CensorEventsStore,
    UIAuthStore,
    CacheInvalidationWorkerStore,
    ServerMetricsStore,
):
    def __init__(self, database: DatabasePool, db_conn, hs):
        self.hs = hs
        self._clock = hs.get_clock()
        self.database_engine = database.engine

        self._presence_id_gen = StreamIdGenerator(
            db_conn, "presence_stream", "stream_id"
        )
        self._device_inbox_id_gen = StreamIdGenerator(
            db_conn, "device_inbox", "stream_id"
        )
        self._public_room_id_gen = StreamIdGenerator(
            db_conn, "public_room_list_stream", "stream_id"
        )
        self._device_list_id_gen = StreamIdGenerator(
            db_conn,
            "device_lists_stream",
            "stream_id",
            extra_tables=[
                ("user_signature_stream", "stream_id"),
                ("device_lists_outbound_pokes", "stream_id"),
            ],
        )
        self._cross_signing_id_gen = StreamIdGenerator(
            db_conn, "e2e_cross_signing_keys", "stream_id"
        )

        self._access_tokens_id_gen = IdGenerator(db_conn, "access_tokens", "id")
        self._event_reports_id_gen = IdGenerator(db_conn, "event_reports", "id")
        self._push_rule_id_gen = IdGenerator(db_conn, "push_rules", "id")
        self._push_rules_enable_id_gen = IdGenerator(db_conn, "push_rules_enable", "id")
        self._pushers_id_gen = StreamIdGenerator(
            db_conn, "pushers", "id", extra_tables=[("deleted_pushers", "stream_id")]
        )
        self._group_updates_id_gen = StreamIdGenerator(
            db_conn, "local_group_updates", "stream_id"
        )

        if isinstance(self.database_engine, PostgresEngine):
            # We set the `writers` to an empty list here as we don't care about
            # missing updates over restarts, as we'll not have anything in our
            # caches to invalidate. (This reduces the amount of writes to the DB
            # that happen).
            self._cache_id_gen = MultiWriterIdGenerator(
                db_conn,
                database,
                stream_name="caches",
                instance_name=hs.get_instance_name(),
                table="cache_invalidation_stream_by_instance",
                instance_column="instance_name",
                id_column="stream_id",
                sequence_name="cache_invalidation_stream_seq",
                writers=[],
            )
        else:
            self._cache_id_gen = None

        super().__init__(database, db_conn, hs)

        self._presence_on_startup = self._get_active_presence(db_conn)

        presence_cache_prefill, min_presence_val = self.db_pool.get_cache_dict(
            db_conn,
            "presence_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self._presence_id_gen.get_current_token(),
        )
        self.presence_stream_cache = StreamChangeCache(
            "PresenceStreamChangeCache",
            min_presence_val,
            prefilled_cache=presence_cache_prefill,
        )

        max_device_inbox_id = self._device_inbox_id_gen.get_current_token()
        device_inbox_prefill, min_device_inbox_id = self.db_pool.get_cache_dict(
            db_conn,
            "device_inbox",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=max_device_inbox_id,
            limit=1000,
        )
        self._device_inbox_stream_cache = StreamChangeCache(
            "DeviceInboxStreamChangeCache",
            min_device_inbox_id,
            prefilled_cache=device_inbox_prefill,
        )
        # The federation outbox and the local device inbox uses the same
        # stream_id generator.
        device_outbox_prefill, min_device_outbox_id = self.db_pool.get_cache_dict(
            db_conn,
            "device_federation_outbox",
            entity_column="destination",
            stream_column="stream_id",
            max_value=max_device_inbox_id,
            limit=1000,
        )
        self._device_federation_outbox_stream_cache = StreamChangeCache(
            "DeviceFederationOutboxStreamChangeCache",
            min_device_outbox_id,
            prefilled_cache=device_outbox_prefill,
        )

        device_list_max = self._device_list_id_gen.get_current_token()
        self._device_list_stream_cache = StreamChangeCache(
            "DeviceListStreamChangeCache", device_list_max
        )
        self._user_signature_stream_cache = StreamChangeCache(
            "UserSignatureStreamChangeCache", device_list_max
        )
        self._device_list_federation_stream_cache = StreamChangeCache(
            "DeviceListFederationStreamChangeCache", device_list_max
        )

        events_max = self._stream_id_gen.get_current_token()
        curr_state_delta_prefill, min_curr_state_delta_id = self.db_pool.get_cache_dict(
            db_conn,
            "current_state_delta_stream",
            entity_column="room_id",
            stream_column="stream_id",
            max_value=events_max,  # As we share the stream id with events token
            limit=1000,
        )
        self._curr_state_delta_stream_cache = StreamChangeCache(
            "_curr_state_delta_stream_cache",
            min_curr_state_delta_id,
            prefilled_cache=curr_state_delta_prefill,
        )

        _group_updates_prefill, min_group_updates_id = self.db_pool.get_cache_dict(
            db_conn,
            "local_group_updates",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self._group_updates_id_gen.get_current_token(),
            limit=1000,
        )
        self._group_updates_stream_cache = StreamChangeCache(
            "_group_updates_stream_cache",
            min_group_updates_id,
            prefilled_cache=_group_updates_prefill,
        )

        self._stream_order_on_start = self.get_room_max_stream_ordering()
        self._min_stream_order_on_start = self.get_room_min_stream_ordering()

        # Used in _generate_user_daily_visits to keep track of progress
        self._last_user_visit_update = self._get_start_of_day()

    def get_device_stream_token(self) -> int:
        return self._device_list_id_gen.get_current_token()

    def take_presence_startup_info(self):
        active_on_startup = self._presence_on_startup
        self._presence_on_startup = None
        return active_on_startup

    def _get_active_presence(self, db_conn):
        """Fetch non-offline presence from the database so that we can register
        the appropriate time outs.
        """

        sql = (
            "SELECT user_id, state, last_active_ts, last_federation_update_ts,"
            " last_user_sync_ts, status_msg, currently_active FROM presence_stream"
            " WHERE state != ?"
        )
        sql = self.database_engine.convert_param_style(sql)

        txn = db_conn.cursor()
        txn.execute(sql, (PresenceState.OFFLINE,))
        rows = self.db_pool.cursor_to_dict(txn)
        txn.close()

        for row in rows:
            row["currently_active"] = bool(row["currently_active"])

        return [UserPresenceState(**row) for row in rows]

    async def count_daily_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 24 hours.
        """
        yesterday = int(self._clock.time_msec()) - (1000 * 60 * 60 * 24)
        return await self.db_pool.runInteraction(
            "count_daily_users", self._count_users, yesterday
        )

    async def count_monthly_users(self) -> int:
        """
        Counts the number of users who used this homeserver in the last 30 days.
        Note this method is intended for phonehome metrics only and is different
        from the mau figure in synapse.storage.monthly_active_users which,
        amongst other things, includes a 3 day grace period before a user counts.
        """
        thirty_days_ago = int(self._clock.time_msec()) - (1000 * 60 * 60 * 24 * 30)
        return await self.db_pool.runInteraction(
            "count_monthly_users", self._count_users, thirty_days_ago
        )

    def _count_users(self, txn, time_from):
        """
        Returns number of users seen in the past time_from period
        """
        sql = """
            SELECT COALESCE(count(*), 0) FROM (
                SELECT user_id FROM user_ips
                WHERE last_seen > ?
                GROUP BY user_id
            ) u
        """
        txn.execute(sql, (time_from,))
        (count,) = txn.fetchone()
        return count

    async def count_r30_users(self) -> Dict[str, int]:
        """
        Counts the number of 30 day retained users, defined as:-
         * Users who have created their accounts more than 30 days ago
         * Where last seen at most 30 days ago
         * Where account creation and last_seen are > 30 days apart

        Returns:
             A mapping of counts globally as well as broken out by platform.
        """

        def _count_r30_users(txn):
            thirty_days_in_secs = 86400 * 30
            now = int(self._clock.time())
            thirty_days_ago_in_secs = now - thirty_days_in_secs

            sql = """
                SELECT platform, COALESCE(count(*), 0) FROM (
                     SELECT
                        users.name, platform, users.creation_ts * 1000,
                        MAX(uip.last_seen)
                     FROM users
                     INNER JOIN (
                         SELECT
                         user_id,
                         last_seen,
                         CASE
                             WHEN user_agent LIKE '%%Android%%' THEN 'android'
                             WHEN user_agent LIKE '%%iOS%%' THEN 'ios'
                             WHEN user_agent LIKE '%%Electron%%' THEN 'electron'
                             WHEN user_agent LIKE '%%Mozilla%%' THEN 'web'
                             WHEN user_agent LIKE '%%Gecko%%' THEN 'web'
                             ELSE 'unknown'
                         END
                         AS platform
                         FROM user_ips
                     ) uip
                     ON users.name = uip.user_id
                     AND users.appservice_id is NULL
                     AND users.creation_ts < ?
                     AND uip.last_seen/1000 > ?
                     AND (uip.last_seen/1000) - users.creation_ts > 86400 * 30
                     GROUP BY users.name, platform, users.creation_ts
                ) u GROUP BY platform
            """

            results = {}
            txn.execute(sql, (thirty_days_ago_in_secs, thirty_days_ago_in_secs))

            for row in txn:
                if row[0] == "unknown":
                    pass
                results[row[0]] = row[1]

            sql = """
                SELECT COALESCE(count(*), 0) FROM (
                    SELECT users.name, users.creation_ts * 1000,
                                                        MAX(uip.last_seen)
                    FROM users
                    INNER JOIN (
                        SELECT
                        user_id,
                        last_seen
                        FROM user_ips
                    ) uip
                    ON users.name = uip.user_id
                    AND appservice_id is NULL
                    AND users.creation_ts < ?
                    AND uip.last_seen/1000 > ?
                    AND (uip.last_seen/1000) - users.creation_ts > 86400 * 30
                    GROUP BY users.name, users.creation_ts
                ) u
            """

            txn.execute(sql, (thirty_days_ago_in_secs, thirty_days_ago_in_secs))

            (count,) = txn.fetchone()
            results["all"] = count

            return results

        return await self.db_pool.runInteraction("count_r30_users", _count_r30_users)

    def _get_start_of_day(self):
        """
        Returns millisecond unixtime for start of UTC day.
        """
        now = time.gmtime()
        today_start = calendar.timegm((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0))
        return today_start * 1000

    async def generate_user_daily_visits(self) -> None:
        """
        Generates daily visit data for use in cohort/ retention analysis
        """

        def _generate_user_daily_visits(txn):
            logger.info("Calling _generate_user_daily_visits")
            today_start = self._get_start_of_day()
            a_day_in_milliseconds = 24 * 60 * 60 * 1000
            now = self.clock.time_msec()

            sql = """
                INSERT INTO user_daily_visits (user_id, device_id, timestamp)
                    SELECT u.user_id, u.device_id, ?
                    FROM user_ips AS u
                    LEFT JOIN (
                      SELECT user_id, device_id, timestamp FROM user_daily_visits
                      WHERE timestamp = ?
                    ) udv
                    ON u.user_id = udv.user_id AND u.device_id=udv.device_id
                    INNER JOIN users ON users.name=u.user_id
                    WHERE last_seen > ? AND last_seen <= ?
                    AND udv.timestamp IS NULL AND users.is_guest=0
                    AND users.appservice_id IS NULL
                    GROUP BY u.user_id, u.device_id
            """

            # This means that the day has rolled over but there could still
            # be entries from the previous day. There is an edge case
            # where if the user logs in at 23:59 and overwrites their
            # last_seen at 00:01 then they will not be counted in the
            # previous day's stats - it is important that the query is run
            # often to minimise this case.
            if today_start > self._last_user_visit_update:
                yesterday_start = today_start - a_day_in_milliseconds
                txn.execute(
                    sql,
                    (
                        yesterday_start,
                        yesterday_start,
                        self._last_user_visit_update,
                        today_start,
                    ),
                )
                self._last_user_visit_update = today_start

            txn.execute(
                sql, (today_start, today_start, self._last_user_visit_update, now)
            )
            # Update _last_user_visit_update to now. The reason to do this
            # rather just clamping to the beginning of the day is to limit
            # the size of the join - meaning that the query can be run more
            # frequently
            self._last_user_visit_update = now

        await self.db_pool.runInteraction(
            "generate_user_daily_visits", _generate_user_daily_visits
        )

    async def get_users(self) -> List[Dict[str, Any]]:
        """Function to retrieve a list of users in users table.

        Returns:
            A list of dictionaries representing users.
        """
        return await self.db_pool.simple_select_list(
            table="users",
            keyvalues={},
            retcols=[
                "name",
                "password_hash",
                "is_guest",
                "admin",
                "user_type",
                "deactivated",
            ],
            desc="get_users",
        )

    async def get_users_paginate(
        self,
        start: int,
        limit: int,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
        guests: bool = True,
        deactivated: bool = False,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Function to retrieve a paginated list of users from
        users list. This will return a json list of users and the
        total number of users matching the filter criteria.

        Args:
            start: start number to begin the query from
            limit: number of rows to retrieve
            user_id: search for user_id. ignored if name is not None
            name: search for local part of user_id or display name
            guests: whether to in include guest users
            deactivated: whether to include deactivated users
        Returns:
            A tuple of a list of mappings from user to information and a count of total users.
        """

        def get_users_paginate_txn(txn):
            filters = []
            args = [self.hs.config.server_name]

            if name:
                filters.append("(name LIKE ? OR displayname LIKE ?)")
                args.extend(["@%" + name + "%:%", "%" + name + "%"])
            elif user_id:
                filters.append("name LIKE ?")
                args.extend(["%" + user_id + "%"])

            if not guests:
                filters.append("is_guest = 0")

            if not deactivated:
                filters.append("deactivated = 0")

            where_clause = "WHERE " + " AND ".join(filters) if len(filters) > 0 else ""

            sql_base = """
                FROM users as u
                LEFT JOIN profiles AS p ON u.name = '@' || p.user_id || ':' || ?
                {}
                """.format(
                where_clause
            )
            sql = "SELECT COUNT(*) as total_users " + sql_base
            txn.execute(sql, args)
            count = txn.fetchone()[0]

            sql = (
                "SELECT name, user_type, is_guest, admin, deactivated, displayname, avatar_url "
                + sql_base
                + " ORDER BY u.name LIMIT ? OFFSET ?"
            )
            args += [limit, start]
            txn.execute(sql, args)
            users = self.db_pool.cursor_to_dict(txn)
            return users, count

        return await self.db_pool.runInteraction(
            "get_users_paginate_txn", get_users_paginate_txn
        )

    async def search_users(self, term: str) -> Optional[List[Dict[str, Any]]]:
        """Function to search users list for one or more users with
        the matched term.

        Args:
            term: search term

        Returns:
            A list of dictionaries or None.
        """
        return await self.db_pool.simple_search_list(
            table="users",
            term=term,
            col="name",
            retcols=["name", "password_hash", "is_guest", "admin", "user_type"],
            desc="search_users",
        )


def check_database_before_upgrade(cur, database_engine, config: HomeServerConfig):
    """Called before upgrading an existing database to check that it is broadly sane
    compared with the configuration.
    """
    logger.info("Checking database for consistency with configuration...")

    # if there are any users in the database, check that the username matches our
    # configured server name.

    cur.execute("SELECT name FROM users LIMIT 1")
    rows = cur.fetchall()
    if not rows:
        return

    user_domain = get_domain_from_id(rows[0][0])
    if user_domain == config.server_name:
        return

    raise Exception(
        "Found users in database not native to %s!\n"
        "You cannot change a synapse server_name after it's been configured"
        % (config.server_name,)
    )


__all__ = ["DataStore", "check_database_before_upgrade"]

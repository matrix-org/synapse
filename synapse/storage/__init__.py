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

from synapse.storage.devices import DeviceStore
from .appservice import (
    ApplicationServiceStore, ApplicationServiceTransactionStore
)
from .directory import DirectoryStore
from .events import EventsStore
from .presence import PresenceStore, UserPresenceState
from .profile import ProfileStore
from .registration import RegistrationStore
from .room import RoomStore
from .roommember import RoomMemberStore
from .stream import StreamStore
from .transactions import TransactionStore
from .keys import KeyStore
from .event_federation import EventFederationStore
from .pusher import PusherStore
from .push_rule import PushRuleStore
from .media_repository import MediaRepositoryStore
from .rejections import RejectionsStore
from .event_push_actions import EventPushActionsStore
from .deviceinbox import DeviceInboxStore
from .group_server import GroupServerStore
from .state import StateStore
from .signatures import SignatureStore
from .filtering import FilteringStore
from .end_to_end_keys import EndToEndKeyStore

from .receipts import ReceiptsStore
from .search import SearchStore
from .tags import TagsStore
from .account_data import AccountDataStore
from .openid import OpenIdStore
from .client_ips import ClientIpStore
from .user_directory import UserDirectoryStore

from .util.id_generators import IdGenerator, StreamIdGenerator, ChainedIdGenerator
from .engines import PostgresEngine

from synapse.api.constants import PresenceState
from synapse.util.caches.stream_change_cache import StreamChangeCache


import logging


logger = logging.getLogger(__name__)


class DataStore(RoomMemberStore, RoomStore,
                RegistrationStore, StreamStore, ProfileStore,
                PresenceStore, TransactionStore,
                DirectoryStore, KeyStore, StateStore, SignatureStore,
                ApplicationServiceStore,
                EventFederationStore,
                MediaRepositoryStore,
                RejectionsStore,
                FilteringStore,
                PusherStore,
                PushRuleStore,
                ApplicationServiceTransactionStore,
                EventsStore,
                ReceiptsStore,
                EndToEndKeyStore,
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
                ):

    def __init__(self, db_conn, hs):
        self.hs = hs
        self._clock = hs.get_clock()
        self.database_engine = hs.database_engine

        self._stream_id_gen = StreamIdGenerator(
            db_conn, "events", "stream_ordering",
            extra_tables=[("local_invites", "stream_id")]
        )
        self._backfill_id_gen = StreamIdGenerator(
            db_conn, "events", "stream_ordering", step=-1,
            extra_tables=[("ex_outlier_stream", "event_stream_ordering")]
        )
        self._presence_id_gen = StreamIdGenerator(
            db_conn, "presence_stream", "stream_id"
        )
        self._device_inbox_id_gen = StreamIdGenerator(
            db_conn, "device_max_stream_id", "stream_id"
        )
        self._public_room_id_gen = StreamIdGenerator(
            db_conn, "public_room_list_stream", "stream_id"
        )
        self._device_list_id_gen = StreamIdGenerator(
            db_conn, "device_lists_stream", "stream_id",
        )

        self._transaction_id_gen = IdGenerator(db_conn, "sent_transactions", "id")
        self._access_tokens_id_gen = IdGenerator(db_conn, "access_tokens", "id")
        self._event_reports_id_gen = IdGenerator(db_conn, "event_reports", "id")
        self._push_rule_id_gen = IdGenerator(db_conn, "push_rules", "id")
        self._push_rules_enable_id_gen = IdGenerator(db_conn, "push_rules_enable", "id")
        self._push_rules_stream_id_gen = ChainedIdGenerator(
            self._stream_id_gen, db_conn, "push_rules_stream", "stream_id"
        )
        self._pushers_id_gen = StreamIdGenerator(
            db_conn, "pushers", "id",
            extra_tables=[("deleted_pushers", "stream_id")],
        )
        self._group_updates_id_gen = StreamIdGenerator(
            db_conn, "local_group_updates", "stream_id",
        )

        if isinstance(self.database_engine, PostgresEngine):
            self._cache_id_gen = StreamIdGenerator(
                db_conn, "cache_invalidation_stream", "stream_id",
            )
        else:
            self._cache_id_gen = None

        self._presence_on_startup = self._get_active_presence(db_conn)

        presence_cache_prefill, min_presence_val = self._get_cache_dict(
            db_conn, "presence_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self._presence_id_gen.get_current_token(),
        )
        self.presence_stream_cache = StreamChangeCache(
            "PresenceStreamChangeCache", min_presence_val,
            prefilled_cache=presence_cache_prefill
        )

        max_device_inbox_id = self._device_inbox_id_gen.get_current_token()
        device_inbox_prefill, min_device_inbox_id = self._get_cache_dict(
            db_conn, "device_inbox",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=max_device_inbox_id,
            limit=1000,
        )
        self._device_inbox_stream_cache = StreamChangeCache(
            "DeviceInboxStreamChangeCache", min_device_inbox_id,
            prefilled_cache=device_inbox_prefill,
        )
        # The federation outbox and the local device inbox uses the same
        # stream_id generator.
        device_outbox_prefill, min_device_outbox_id = self._get_cache_dict(
            db_conn, "device_federation_outbox",
            entity_column="destination",
            stream_column="stream_id",
            max_value=max_device_inbox_id,
            limit=1000,
        )
        self._device_federation_outbox_stream_cache = StreamChangeCache(
            "DeviceFederationOutboxStreamChangeCache", min_device_outbox_id,
            prefilled_cache=device_outbox_prefill,
        )

        device_list_max = self._device_list_id_gen.get_current_token()
        self._device_list_stream_cache = StreamChangeCache(
            "DeviceListStreamChangeCache", device_list_max,
        )
        self._device_list_federation_stream_cache = StreamChangeCache(
            "DeviceListFederationStreamChangeCache", device_list_max,
        )

        events_max = self._stream_id_gen.get_current_token()
        curr_state_delta_prefill, min_curr_state_delta_id = self._get_cache_dict(
            db_conn, "current_state_delta_stream",
            entity_column="room_id",
            stream_column="stream_id",
            max_value=events_max,  # As we share the stream id with events token
            limit=1000,
        )
        self._curr_state_delta_stream_cache = StreamChangeCache(
            "_curr_state_delta_stream_cache", min_curr_state_delta_id,
            prefilled_cache=curr_state_delta_prefill,
        )

        _group_updates_prefill, min_group_updates_id = self._get_cache_dict(
            db_conn, "local_group_updates",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self._group_updates_id_gen.get_current_token(),
            limit=1000,
        )
        self._group_updates_stream_cache = StreamChangeCache(
            "_group_updates_stream_cache", min_group_updates_id,
            prefilled_cache=_group_updates_prefill,
        )

        self._stream_order_on_start = self.get_room_max_stream_ordering()
        self._min_stream_order_on_start = self.get_room_min_stream_ordering()

        super(DataStore, self).__init__(db_conn, hs)

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
        rows = self.cursor_to_dict(txn)
        txn.close()

        for row in rows:
            row["currently_active"] = bool(row["currently_active"])

        return [UserPresenceState(**row) for row in rows]

    def count_daily_users(self):
        """
        Counts the number of users who used this homeserver in the last 24 hours.
        """
        def _count_users(txn):
            yesterday = int(self._clock.time_msec()) - (1000 * 60 * 60 * 24)

            sql = """
                SELECT COALESCE(count(*), 0) FROM (
                    SELECT user_id FROM user_ips
                    WHERE last_seen > ?
                    GROUP BY user_id
                ) u
            """

            txn.execute(sql, (yesterday,))
            count, = txn.fetchone()
            return count

        return self.runInteraction("count_users", _count_users)

    def count_r30_users(self):
        """
        Counts the number of 30 day retained users, defined as:-
         * Users who have created their accounts more than 30 days ago
         * Where last seen at most 30 days ago
         * Where account creation and last_seen are > 30 days apart

         Returns counts globaly for a given user as well as breaking
         by platform
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
            txn.execute(sql, (thirty_days_ago_in_secs,
                              thirty_days_ago_in_secs))

            for row in txn:
                if row[0] is 'unknown':
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

            txn.execute(sql, (thirty_days_ago_in_secs,
                              thirty_days_ago_in_secs))

            count, = txn.fetchone()
            results['all'] = count

            return results

        return self.runInteraction("count_r30_users", _count_r30_users)

    def get_users(self):
        """Function to reterive a list of users in users table.

        Args:
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]
        """
        return self._simple_select_list(
            table="users",
            keyvalues={},
            retcols=[
                "name",
                "password_hash",
                "is_guest",
                "admin"
            ],
            desc="get_users",
        )

    def get_users_paginate(self, order, start, limit):
        """Function to reterive a paginated list of users from
        users list. This will return a json object, which contains
        list of users and the total number of users in users table.

        Args:
            order (str): column name to order the select by this column
            start (int): start number to begin the query from
            limit (int): number of rows to reterive
        Returns:
            defer.Deferred: resolves to json object {list[dict[str, Any]], count}
        """
        is_guest = 0
        i_start = (int)(start)
        i_limit = (int)(limit)
        return self.get_user_list_paginate(
            table="users",
            keyvalues={
                "is_guest": is_guest
            },
            pagevalues=[
                order,
                i_limit,
                i_start
            ],
            retcols=[
                "name",
                "password_hash",
                "is_guest",
                "admin"
            ],
            desc="get_users_paginate",
        )

    def search_users(self, term):
        """Function to search users list for one or more users with
        the matched term.

        Args:
            term (str): search term
            col (str): column to query term should be matched to
        Returns:
            defer.Deferred: resolves to list[dict[str, Any]]
        """
        return self._simple_search_list(
            table="users",
            term=term,
            col="name",
            retcols=[
                "name",
                "password_hash",
                "is_guest",
                "admin"
            ],
            desc="search_users",
        )


def are_all_users_on_domain(txn, database_engine, domain):
    sql = database_engine.convert_param_style(
        "SELECT COUNT(*) FROM users WHERE name NOT LIKE ?"
    )
    pat = "%:" + domain
    txn.execute(sql, (pat,))
    num_not_matching = txn.fetchall()[0][0]
    if num_not_matching == 0:
        return True
    return False

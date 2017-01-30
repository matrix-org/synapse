# -*- coding: utf-8 -*-
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

from twisted.internet import defer

from synapse.storage.devices import DeviceStore
from .appservice import (
    ApplicationServiceStore, ApplicationServiceTransactionStore
)
from ._base import LoggingTransaction
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
        self._receipts_id_gen = StreamIdGenerator(
            db_conn, "receipts_linearized", "stream_id"
        )
        self._account_data_id_gen = StreamIdGenerator(
            db_conn, "account_data_max_stream_id", "stream_id"
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
        self._state_groups_id_gen = IdGenerator(db_conn, "state_groups", "id")
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

        if isinstance(self.database_engine, PostgresEngine):
            self._cache_id_gen = StreamIdGenerator(
                db_conn, "cache_invalidation_stream", "stream_id",
            )
        else:
            self._cache_id_gen = None

        events_max = self._stream_id_gen.get_current_token()
        event_cache_prefill, min_event_val = self._get_cache_dict(
            db_conn, "events",
            entity_column="room_id",
            stream_column="stream_ordering",
            max_value=events_max,
        )
        self._events_stream_cache = StreamChangeCache(
            "EventsRoomStreamChangeCache", min_event_val,
            prefilled_cache=event_cache_prefill,
        )

        self._membership_stream_cache = StreamChangeCache(
            "MembershipStreamChangeCache", events_max,
        )

        account_max = self._account_data_id_gen.get_current_token()
        self._account_data_stream_cache = StreamChangeCache(
            "AccountDataAndTagsChangeCache", account_max,
        )

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

        push_rules_prefill, push_rules_id = self._get_cache_dict(
            db_conn, "push_rules_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self._push_rules_stream_id_gen.get_current_token()[0],
        )

        self.push_rules_stream_cache = StreamChangeCache(
            "PushRulesStreamChangeCache", push_rules_id,
            prefilled_cache=push_rules_prefill,
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

        cur = LoggingTransaction(
            db_conn.cursor(),
            name="_find_stream_orderings_for_times_txn",
            database_engine=self.database_engine,
            after_callbacks=[]
        )
        self._find_stream_orderings_for_times_txn(cur)
        cur.close()

        self.find_stream_orderings_looping_call = self._clock.looping_call(
            self._find_stream_orderings_for_times, 60 * 60 * 1000
        )

        self._stream_order_on_start = self.get_room_max_stream_ordering()
        self._min_stream_order_on_start = self.get_room_min_stream_ordering()

        super(DataStore, self).__init__(hs)

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

    @defer.inlineCallbacks
    def count_daily_users(self):
        """
        Counts the number of users who used this homeserver in the last 24 hours.
        """
        def _count_users(txn):
            txn.execute(
                "SELECT COUNT(DISTINCT user_id) AS users"
                " FROM user_ips"
                " WHERE last_seen > ?",
                # This is close enough to a day for our purposes.
                (int(self._clock.time_msec()) - (1000 * 60 * 60 * 24),)
            )
            rows = self.cursor_to_dict(txn)
            if rows:
                return rows[0]["users"]
            return 0

        ret = yield self.runInteraction("count_users", _count_users)
        defer.returnValue(ret)

    def get_user_ip_and_agents(self, user):
        return self._simple_select_list(
            table="user_ips",
            keyvalues={"user_id": user.to_string()},
            retcols=[
                "access_token", "ip", "user_agent", "last_seen"
            ],
            desc="get_user_ip_and_agents",
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

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
from .appservice import (
    ApplicationServiceStore, ApplicationServiceTransactionStore
)
from ._base import Cache
from .directory import DirectoryStore
from .events import EventsStore
from .presence import PresenceStore
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

from .state import StateStore
from .signatures import SignatureStore
from .filtering import FilteringStore
from .end_to_end_keys import EndToEndKeyStore

from .receipts import ReceiptsStore
from .search import SearchStore
from .tags import TagsStore
from .account_data import AccountDataStore

from util.id_generators import IdGenerator, StreamIdGenerator

from synapse.util.caches.stream_change_cache import StreamChangeCache


import logging


logger = logging.getLogger(__name__)


# Number of msec of granularity to store the user IP 'last seen' time. Smaller
# times give more inserts into the database even for readonly API hits
# 120 seconds == 2 minutes
LAST_SEEN_GRANULARITY = 120*1000


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
                EventPushActionsStore
                ):

    def __init__(self, db_conn, hs):
        self.hs = hs
        self.database_engine = hs.database_engine

        cur = db_conn.cursor()
        try:
            cur.execute("SELECT MIN(stream_ordering) FROM events",)
            rows = cur.fetchall()
            self.min_stream_token = rows[0][0] if rows and rows[0] and rows[0][0] else -1
            self.min_stream_token = min(self.min_stream_token, -1)
        finally:
            cur.close()

        self.client_ip_last_seen = Cache(
            name="client_ip_last_seen",
            keylen=4,
        )

        self._stream_id_gen = StreamIdGenerator(
            db_conn, "events", "stream_ordering"
        )
        self._receipts_id_gen = StreamIdGenerator(
            db_conn, "receipts_linearized", "stream_id"
        )
        self._account_data_id_gen = StreamIdGenerator(
            db_conn, "account_data_max_stream_id", "stream_id"
        )

        self._transaction_id_gen = IdGenerator("sent_transactions", "id", self)
        self._state_groups_id_gen = IdGenerator("state_groups", "id", self)
        self._access_tokens_id_gen = IdGenerator("access_tokens", "id", self)
        self._refresh_tokens_id_gen = IdGenerator("refresh_tokens", "id", self)
        self._pushers_id_gen = IdGenerator("pushers", "id", self)
        self._push_rule_id_gen = IdGenerator("push_rules", "id", self)
        self._push_rules_enable_id_gen = IdGenerator("push_rules_enable", "id", self)

        events_max = self._stream_id_gen.get_max_token(None)
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

        account_max = self._account_data_id_gen.get_max_token(None)
        self._account_data_stream_cache = StreamChangeCache(
            "AccountDataAndTagsChangeCache", account_max,
        )

        super(DataStore, self).__init__(hs)

    def _get_cache_dict(self, db_conn, table, entity_column, stream_column, max_value):
        # Fetch a mapping of room_id -> max stream position for "recent" rooms.
        # It doesn't really matter how many we get, the StreamChangeCache will
        # do the right thing to ensure it respects the max size of cache.
        sql = (
            "SELECT %(entity)s, MAX(%(stream)s) FROM %(table)s"
            " WHERE %(stream)s > ? - 100000"
            " GROUP BY %(entity)s"
        ) % {
            "table": table,
            "entity": entity_column,
            "stream": stream_column,
        }

        sql = self.database_engine.convert_param_style(sql)

        txn = db_conn.cursor()
        txn.execute(sql, (int(max_value),))
        rows = txn.fetchall()

        cache = {
            row[0]: int(row[1])
            for row in rows
        }

        if cache:
            min_val = min(cache.values())
        else:
            min_val = max_value

        return cache, min_val

    @defer.inlineCallbacks
    def insert_client_ip(self, user, access_token, ip, user_agent):
        now = int(self._clock.time_msec())
        key = (user.to_string(), access_token, ip)

        try:
            last_seen = self.client_ip_last_seen.get(key)
        except KeyError:
            last_seen = None

        # Rate-limited inserts
        if last_seen is not None and (now - last_seen) < LAST_SEEN_GRANULARITY:
            defer.returnValue(None)

        self.client_ip_last_seen.prefill(key, now)

        # It's safe not to lock here: a) no unique constraint,
        # b) LAST_SEEN_GRANULARITY makes concurrent updates incredibly unlikely
        yield self._simple_upsert(
            "user_ips",
            keyvalues={
                "user_id": user.to_string(),
                "access_token": access_token,
                "ip": ip,
                "user_agent": user_agent,
            },
            values={
                "last_seen": now,
            },
            desc="insert_client_ip",
            lock=False,
        )

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

# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from ._base import SQLBaseStore, Table
from twisted.internet import defer

from synapse.api.errors import StoreError

from syutil.jsonutil import encode_canonical_json

import logging
import simplejson as json

logger = logging.getLogger(__name__)


class PusherStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_pushers_by_app_id_and_pushkey(self, app_id_and_pushkey):
        sql = (
            "SELECT id, user_name, kind, profile_tag, app_id,"
            "app_display_name, device_display_name, pushkey, ts, data, "
            "last_token, last_success, failing_since "
            "FROM pushers "
            "WHERE app_id = ? AND pushkey = ?"
        )

        rows = yield self._execute(
            "get_pushers_by_app_id_and_pushkey", None, sql,
            app_id_and_pushkey[0], app_id_and_pushkey[1]
        )

        ret = [
            {
                "id": r[0],
                "user_name": r[1],
                "kind": r[2],
                "profile_tag": r[3],
                "app_id": r[4],
                "app_display_name": r[5],
                "device_display_name": r[6],
                "pushkey": r[7],
                "pushkey_ts": r[8],
                "data": json.loads(r[9]),
                "last_token": r[10],
                "last_success": r[11],
                "failing_since": r[12]
            }
            for r in rows
        ]

        defer.returnValue(ret[0])

    @defer.inlineCallbacks
    def get_all_pushers(self):
        sql = (
            "SELECT id, user_name, kind, profile_tag, app_id,"
            "app_display_name, device_display_name, pushkey, ts, data, "
            "last_token, last_success, failing_since "
            "FROM pushers"
        )

        rows = yield self._execute("get_all_pushers", None, sql)

        ret = [
            {
                "id": r[0],
                "user_name": r[1],
                "kind": r[2],
                "profile_tag": r[3],
                "app_id": r[4],
                "app_display_name": r[5],
                "device_display_name": r[6],
                "pushkey": r[7],
                "pushkey_ts": r[8],
                "data": json.loads(r[9]),
                "last_token": r[10],
                "last_success": r[11],
                "failing_since": r[12]
            }
            for r in rows
        ]

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def add_pusher(self, user_name, profile_tag, kind, app_id,
                   app_display_name, device_display_name,
                   pushkey, pushkey_ts, lang, data):
        try:
            next_id = yield self._pushers_id_gen.get_next()
            yield self._simple_upsert(
                PushersTable.table_name,
                dict(
                    app_id=app_id,
                    pushkey=pushkey,
                ),
                dict(
                    user_name=user_name,
                    kind=kind,
                    profile_tag=profile_tag,
                    app_display_name=app_display_name,
                    device_display_name=device_display_name,
                    ts=pushkey_ts,
                    lang=lang,
                    data=encode_canonical_json(data).decode("UTF-8"),
                ),
                insertion_values=dict(
                    id=next_id,
                ),
                desc="add_pusher",
            )
        except Exception as e:
            logger.error("create_pusher with failed: %s", e)
            raise StoreError(500, "Problem creating pusher.")

    @defer.inlineCallbacks
    def delete_pusher_by_app_id_pushkey(self, app_id, pushkey):
        yield self._simple_delete_one(
            PushersTable.table_name,
            {"app_id": app_id, "pushkey": pushkey},
            desc="delete_pusher_by_app_id_pushkey",
        )

    @defer.inlineCallbacks
    def update_pusher_last_token(self, app_id, pushkey, last_token):
        yield self._simple_update_one(
            PushersTable.table_name,
            {'app_id': app_id, 'pushkey': pushkey},
            {'last_token': last_token},
            desc="update_pusher_last_token",
        )

    @defer.inlineCallbacks
    def update_pusher_last_token_and_success(self, app_id, pushkey,
                                             last_token, last_success):
        yield self._simple_update_one(
            PushersTable.table_name,
            {'app_id': app_id, 'pushkey': pushkey},
            {'last_token': last_token, 'last_success': last_success},
            desc="update_pusher_last_token_and_success",
        )

    @defer.inlineCallbacks
    def update_pusher_failing_since(self, app_id, pushkey, failing_since):
        yield self._simple_update_one(
            PushersTable.table_name,
            {'app_id': app_id, 'pushkey': pushkey},
            {'failing_since': failing_since},
            desc="update_pusher_failing_since",
        )


class PushersTable(Table):
    table_name = "pushers"

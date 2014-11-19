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

import collections

from ._base import SQLBaseStore, Table
from twisted.internet import defer

from sqlite3 import IntegrityError
from synapse.api.errors import StoreError

import logging

logger = logging.getLogger(__name__)

class PusherStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_all_pushers_after_id(self, min_id):
        sql = (
            "SELECT id, user_name, kind, app, app_display_name, device_display_name, pushkey, data, last_token "
            "FROM pushers "
            "WHERE id > ?"
        )

        rows = yield self._execute(None, sql, min_id)

        ret = [
            {
                "id": r[0],
                "user_name": r[1],
                "kind": r[2],
                "app": r[3],
                "app_display_name": r[4],
                "device_display_name": r[5],
                "pushkey": r[6],
                "data": r[7],
                "last_token": r[8]

            }
            for r in rows
        ]

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def add_pusher(self, user_name, kind, app, app_display_name, device_display_name, pushkey, data):
        try:
            yield self._simple_insert(PushersTable.table_name, dict(
                user_name=user_name,
                kind=kind,
                app=app,
                app_display_name=app_display_name,
                device_display_name=device_display_name,
                pushkey=pushkey,
                data=data
            ))
        except IntegrityError:
            raise StoreError(409, "Pushkey in use.")
        except Exception as e:
            logger.error("create_pusher with failed: %s", e)
            raise StoreError(500, "Problem creating pusher.")

    @defer.inlineCallbacks
    def update_pusher_last_token(self, user_name, pushkey, last_token):
        yield self._simple_update_one(PushersTable.table_name,
                                      {'user_name': user_name, 'pushkey': pushkey},
                                      {'last_token': last_token}
        )


class PushersTable(Table):
    table_name = "pushers"

    fields = [
        "id",
        "user_name",
        "kind",
        "app"
        "app_display_name",
        "device_display_name",
        "pushkey",
        "data",
        "last_token"
    ]

    EntryType = collections.namedtuple("PusherEntry", fields)
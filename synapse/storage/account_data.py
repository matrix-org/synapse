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

from ._base import SQLBaseStore
from twisted.internet import defer

from synapse.util.caches.descriptors import cached, cachedList, cachedInlineCallbacks

import ujson as json
import logging

logger = logging.getLogger(__name__)


class AccountDataStore(SQLBaseStore):

    @cached()
    def get_account_data_for_user(self, user_id):
        """Get all the client account_data for a user.

        Args:
            user_id(str): The user to get the account_data for.
        Returns:
            A deferred pair of a dict of global account_data and a dict
            mapping from room_id string to per room account_data dicts.
        """

        def get_account_data_for_user_txn(txn):
            rows = self._simple_select_list_txn(
                txn, "account_data", {"user_id": user_id},
                ["account_data_type", "content"]
            )

            global_account_data = {
                row["account_data_type"]: json.loads(row["content"]) for row in rows
            }

            rows = self._simple_select_list_txn(
                txn, "room_account_data", {"user_id": user_id},
                ["room_id", "account_data_type", "content"]
            )

            by_room = {}
            for row in rows:
                room_data = by_room.setdefault(row["room_id"], {})
                room_data[row["account_data_type"]] = json.loads(row["content"])

            return (global_account_data, by_room)

        return self.runInteraction(
            "get_account_data_for_user", get_account_data_for_user_txn
        )

    @cachedInlineCallbacks(num_args=2)
    def get_global_account_data_by_type_for_user(self, data_type, user_id):
        """
        Returns:
            Deferred: A dict
        """
        result = yield self._simple_select_one_onecol(
            table="account_data",
            keyvalues={
                "user_id": user_id,
                "account_data_type": data_type,
            },
            retcol="content",
            desc="get_global_account_data_by_type_for_user",
            allow_none=True,
        )

        if result:
            defer.returnValue(json.loads(result))
        else:
            defer.returnValue(None)

    @cachedList(cached_method_name="get_global_account_data_by_type_for_user",
                num_args=2, list_name="user_ids", inlineCallbacks=True)
    def get_global_account_data_by_type_for_users(self, data_type, user_ids):
        rows = yield self._simple_select_many_batch(
            table="account_data",
            column="user_id",
            iterable=user_ids,
            keyvalues={
                "account_data_type": data_type,
            },
            retcols=("user_id", "content",),
            desc="get_global_account_data_by_type_for_users",
        )

        defer.returnValue({
            row["user_id"]: json.loads(row["content"]) if row["content"] else None
            for row in rows
        })

    def get_account_data_for_room(self, user_id, room_id):
        """Get all the client account_data for a user for a room.

        Args:
            user_id(str): The user to get the account_data for.
            room_id(str): The room to get the account_data for.
        Returns:
            A deferred dict of the room account_data
        """
        def get_account_data_for_room_txn(txn):
            rows = self._simple_select_list_txn(
                txn, "room_account_data", {"user_id": user_id, "room_id": room_id},
                ["account_data_type", "content"]
            )

            return {
                row["account_data_type"]: json.loads(row["content"]) for row in rows
            }

        return self.runInteraction(
            "get_account_data_for_room", get_account_data_for_room_txn
        )

    def get_all_updated_account_data(self, last_global_id, last_room_id,
                                     current_id, limit):
        """Get all the client account_data that has changed on the server
        Args:
            last_global_id(int): The position to fetch from for top level data
            last_room_id(int): The position to fetch from for per room data
            current_id(int): The position to fetch up to.
        Returns:
            A deferred pair of lists of tuples of stream_id int, user_id string,
            room_id string, type string, and content string.
        """
        if last_room_id == current_id and last_global_id == current_id:
            return defer.succeed(([], []))

        def get_updated_account_data_txn(txn):
            sql = (
                "SELECT stream_id, user_id, account_data_type, content"
                " FROM account_data WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_global_id, current_id, limit))
            global_results = txn.fetchall()

            sql = (
                "SELECT stream_id, user_id, room_id, account_data_type, content"
                " FROM room_account_data WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_room_id, current_id, limit))
            room_results = txn.fetchall()
            return (global_results, room_results)
        return self.runInteraction(
            "get_all_updated_account_data_txn", get_updated_account_data_txn
        )

    def get_updated_account_data_for_user(self, user_id, stream_id):
        """Get all the client account_data for a that's changed for a user

        Args:
            user_id(str): The user to get the account_data for.
            stream_id(int): The point in the stream since which to get updates
        Returns:
            A deferred pair of a dict of global account_data and a dict
            mapping from room_id string to per room account_data dicts.
        """

        def get_updated_account_data_for_user_txn(txn):
            sql = (
                "SELECT account_data_type, content FROM account_data"
                " WHERE user_id = ? AND stream_id > ?"
            )

            txn.execute(sql, (user_id, stream_id))

            global_account_data = {
                row[0]: json.loads(row[1]) for row in txn.fetchall()
            }

            sql = (
                "SELECT room_id, account_data_type, content FROM room_account_data"
                " WHERE user_id = ? AND stream_id > ?"
            )

            txn.execute(sql, (user_id, stream_id))

            account_data_by_room = {}
            for row in txn.fetchall():
                room_account_data = account_data_by_room.setdefault(row[0], {})
                room_account_data[row[1]] = json.loads(row[2])

            return (global_account_data, account_data_by_room)

        changed = self._account_data_stream_cache.has_entity_changed(
            user_id, int(stream_id)
        )
        if not changed:
            return ({}, {})

        return self.runInteraction(
            "get_updated_account_data_for_user", get_updated_account_data_for_user_txn
        )

    @defer.inlineCallbacks
    def add_account_data_to_room(self, user_id, room_id, account_data_type, content):
        """Add some account_data to a room for a user.
        Args:
            user_id(str): The user to add a tag for.
            room_id(str): The room to add a tag for.
            account_data_type(str): The type of account_data to add.
            content(dict): A json object to associate with the tag.
        Returns:
            A deferred that completes once the account_data has been added.
        """
        content_json = json.dumps(content)

        def add_account_data_txn(txn, next_id):
            self._simple_upsert_txn(
                txn,
                table="room_account_data",
                keyvalues={
                    "user_id": user_id,
                    "room_id": room_id,
                    "account_data_type": account_data_type,
                },
                values={
                    "stream_id": next_id,
                    "content": content_json,
                }
            )
            txn.call_after(
                self._account_data_stream_cache.entity_has_changed,
                user_id, next_id,
            )
            txn.call_after(self.get_account_data_for_user.invalidate, (user_id,))
            self._update_max_stream_id(txn, next_id)

        with self._account_data_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "add_room_account_data", add_account_data_txn, next_id
            )

        result = self._account_data_id_gen.get_current_token()
        defer.returnValue(result)

    @defer.inlineCallbacks
    def add_account_data_for_user(self, user_id, account_data_type, content):
        """Add some account_data to a room for a user.
        Args:
            user_id(str): The user to add a tag for.
            account_data_type(str): The type of account_data to add.
            content(dict): A json object to associate with the tag.
        Returns:
            A deferred that completes once the account_data has been added.
        """
        content_json = json.dumps(content)

        def add_account_data_txn(txn, next_id):
            self._simple_upsert_txn(
                txn,
                table="account_data",
                keyvalues={
                    "user_id": user_id,
                    "account_data_type": account_data_type,
                },
                values={
                    "stream_id": next_id,
                    "content": content_json,
                }
            )
            txn.call_after(
                self._account_data_stream_cache.entity_has_changed,
                user_id, next_id,
            )
            txn.call_after(self.get_account_data_for_user.invalidate, (user_id,))
            txn.call_after(
                self.get_global_account_data_by_type_for_user.invalidate,
                (account_data_type, user_id,)
            )
            self._update_max_stream_id(txn, next_id)

        with self._account_data_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "add_user_account_data", add_account_data_txn, next_id
            )

        result = self._account_data_id_gen.get_current_token()
        defer.returnValue(result)

    def _update_max_stream_id(self, txn, next_id):
        """Update the max stream_id

        Args:
            txn: The database cursor
            next_id(int): The the revision to advance to.
        """
        update_max_id_sql = (
            "UPDATE account_data_max_stream_id"
            " SET stream_id = ?"
            " WHERE stream_id < ?"
        )
        txn.execute(update_max_id_sql, (next_id, next_id))

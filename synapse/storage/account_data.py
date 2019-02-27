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

import abc
import logging

from canonicaljson import json

from twisted.internet import defer

from synapse.storage._base import SQLBaseStore
from synapse.storage.util.id_generators import StreamIdGenerator
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks
from synapse.util.caches.stream_change_cache import StreamChangeCache

logger = logging.getLogger(__name__)


class AccountDataWorkerStore(SQLBaseStore):
    """This is an abstract base class where subclasses must implement
    `get_max_account_data_stream_id` which can be called in the initializer.
    """

    # This ABCMeta metaclass ensures that we cannot be instantiated without
    # the abstract methods being implemented.
    __metaclass__ = abc.ABCMeta

    def __init__(self, db_conn, hs):
        account_max = self.get_max_account_data_stream_id()
        self._account_data_stream_cache = StreamChangeCache(
            "AccountDataAndTagsChangeCache", account_max,
        )

        super(AccountDataWorkerStore, self).__init__(db_conn, hs)

    @abc.abstractmethod
    def get_max_account_data_stream_id(self):
        """Get the current max stream ID for account data stream

        Returns:
            int
        """
        raise NotImplementedError()

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

    @cachedInlineCallbacks(num_args=2, max_entries=5000)
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

    @cached(num_args=2)
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

    @cached(num_args=3, max_entries=5000)
    def get_account_data_for_room_and_type(self, user_id, room_id, account_data_type):
        """Get the client account_data of given type for a user for a room.

        Args:
            user_id(str): The user to get the account_data for.
            room_id(str): The room to get the account_data for.
            account_data_type (str): The account data type to get.
        Returns:
            A deferred of the room account_data for that type, or None if
            there isn't any set.
        """
        def get_account_data_for_room_and_type_txn(txn):
            content_json = self._simple_select_one_onecol_txn(
                txn,
                table="room_account_data",
                keyvalues={
                    "user_id": user_id,
                    "room_id": room_id,
                    "account_data_type": account_data_type,
                },
                retcol="content",
                allow_none=True
            )

            return json.loads(content_json) if content_json else None

        return self.runInteraction(
            "get_account_data_for_room_and_type",
            get_account_data_for_room_and_type_txn,
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
                row[0]: json.loads(row[1]) for row in txn
            }

            sql = (
                "SELECT room_id, account_data_type, content FROM room_account_data"
                " WHERE user_id = ? AND stream_id > ?"
            )

            txn.execute(sql, (user_id, stream_id))

            account_data_by_room = {}
            for row in txn:
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

    @cachedInlineCallbacks(num_args=2, cache_context=True, max_entries=5000)
    def is_ignored_by(self, ignored_user_id, ignorer_user_id, cache_context):
        ignored_account_data = yield self.get_global_account_data_by_type_for_user(
            "m.ignored_user_list", ignorer_user_id,
            on_invalidate=cache_context.invalidate,
        )
        if not ignored_account_data:
            defer.returnValue(False)

        defer.returnValue(
            ignored_user_id in ignored_account_data.get("ignored_users", {})
        )


class AccountDataStore(AccountDataWorkerStore):
    def __init__(self, db_conn, hs):
        self._account_data_id_gen = StreamIdGenerator(
            db_conn, "account_data_max_stream_id", "stream_id"
        )

        super(AccountDataStore, self).__init__(db_conn, hs)

    def get_max_account_data_stream_id(self):
        """Get the current max stream id for the private user data stream

        Returns:
            A deferred int.
        """
        return self._account_data_id_gen.get_current_token()

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

        with self._account_data_id_gen.get_next() as next_id:
            # no need to lock here as room_account_data has a unique constraint
            # on (user_id, room_id, account_data_type) so _simple_upsert will
            # retry if there is a conflict.
            yield self._simple_upsert(
                desc="add_room_account_data",
                table="room_account_data",
                keyvalues={
                    "user_id": user_id,
                    "room_id": room_id,
                    "account_data_type": account_data_type,
                },
                values={
                    "stream_id": next_id,
                    "content": content_json,
                },
                lock=False,
            )

            # it's theoretically possible for the above to succeed and the
            # below to fail - in which case we might reuse a stream id on
            # restart, and the above update might not get propagated. That
            # doesn't sound any worse than the whole update getting lost,
            # which is what would happen if we combined the two into one
            # transaction.
            yield self._update_max_stream_id(next_id)

            self._account_data_stream_cache.entity_has_changed(user_id, next_id)
            self.get_account_data_for_user.invalidate((user_id,))
            self.get_account_data_for_room.invalidate((user_id, room_id,))
            self.get_account_data_for_room_and_type.prefill(
                (user_id, room_id, account_data_type,), content,
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

        with self._account_data_id_gen.get_next() as next_id:
            # no need to lock here as account_data has a unique constraint on
            # (user_id, account_data_type) so _simple_upsert will retry if
            # there is a conflict.
            yield self._simple_upsert(
                desc="add_user_account_data",
                table="account_data",
                keyvalues={
                    "user_id": user_id,
                    "account_data_type": account_data_type,
                },
                values={
                    "stream_id": next_id,
                    "content": content_json,
                },
                lock=False,
            )

            # it's theoretically possible for the above to succeed and the
            # below to fail - in which case we might reuse a stream id on
            # restart, and the above update might not get propagated. That
            # doesn't sound any worse than the whole update getting lost,
            # which is what would happen if we combined the two into one
            # transaction.
            yield self._update_max_stream_id(next_id)

            self._account_data_stream_cache.entity_has_changed(
                user_id, next_id,
            )
            self.get_account_data_for_user.invalidate((user_id,))
            self.get_global_account_data_by_type_for_user.invalidate(
                (account_data_type, user_id,)
            )

        result = self._account_data_id_gen.get_current_token()
        defer.returnValue(result)

    def _update_max_stream_id(self, next_id):
        """Update the max stream_id

        Args:
            next_id(int): The the revision to advance to.
        """
        def _update(txn):
            update_max_id_sql = (
                "UPDATE account_data_max_stream_id"
                " SET stream_id = ?"
                " WHERE stream_id < ?"
            )
            txn.execute(update_max_id_sql, (next_id, next_id))
        return self.runInteraction(
            "update_account_data_max_stream_id",
            _update,
        )

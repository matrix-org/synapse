# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.api.errors import StoreError, Codes

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cached


class RegistrationStore(SQLBaseStore):

    def __init__(self, hs):
        super(RegistrationStore, self).__init__(hs)

        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def add_access_token_to_user(self, user_id, token):
        """Adds an access token for the given user.

        Args:
            user_id (str): The user ID.
            token (str): The new access token to add.
        Raises:
            StoreError if there was a problem adding this.
        """
        next_id = yield self._access_tokens_id_gen.get_next()

        yield self._simple_insert(
            "access_tokens",
            {
                "id": next_id,
                "user_id": user_id,
                "token": token
            },
            desc="add_access_token_to_user",
        )

    @defer.inlineCallbacks
    def add_refresh_token_to_user(self, user_id, token):
        """Adds a refresh token for the given user.

        Args:
            user_id (str): The user ID.
            token (str): The new refresh token to add.
        Raises:
            StoreError if there was a problem adding this.
        """
        next_id = yield self._refresh_tokens_id_gen.get_next()

        yield self._simple_insert(
            "refresh_tokens",
            {
                "id": next_id,
                "user_id": user_id,
                "token": token
            },
            desc="add_refresh_token_to_user",
        )

    @defer.inlineCallbacks
    def register(self, user_id, token, password_hash):
        """Attempts to register an account.

        Args:
            user_id (str): The desired user ID to register.
            token (str): The desired access token to use for this user.
            password_hash (str): Optional. The password hash for this user.
        Raises:
            StoreError if the user_id could not be registered.
        """
        yield self.runInteraction(
            "register",
            self._register, user_id, token, password_hash
        )

    def _register(self, txn, user_id, token, password_hash):
        now = int(self.clock.time())

        next_id = self._access_tokens_id_gen.get_next_txn(txn)

        try:
            txn.execute("INSERT INTO users(name, password_hash, creation_ts) "
                        "VALUES (?,?,?)",
                        [user_id, password_hash, now])
        except self.database_engine.module.IntegrityError:
            raise StoreError(
                400, "User ID already taken.", errcode=Codes.USER_IN_USE
            )

        if token:
            # it's possible for this to get a conflict, but only for a single user
            # since tokens are namespaced based on their user ID
            txn.execute(
                "INSERT INTO access_tokens(id, user_id, token)"
                " VALUES (?,?,?)",
                (next_id, user_id, token,)
            )

    def get_user_by_id(self, user_id):
        return self._simple_select_one(
            table="users",
            keyvalues={
                "name": user_id,
            },
            retcols=["name", "password_hash"],
            allow_none=True,
        )

    def get_users_by_id_case_insensitive(self, user_id):
        """Gets users that match user_id case insensitively.
        Returns a mapping of user_id -> password_hash.
        """
        def f(txn):
            sql = (
                "SELECT name, password_hash FROM users"
                " WHERE lower(name) = lower(?)"
            )
            txn.execute(sql, (user_id,))
            return dict(txn.fetchall())

        return self.runInteraction("get_users_by_id_case_insensitive", f)

    @defer.inlineCallbacks
    def user_set_password_hash(self, user_id, password_hash):
        """
        NB. This does *not* evict any cache because the one use for this
            removes most of the entries subsequently anyway so it would be
            pointless. Use flush_user separately.
        """
        yield self._simple_update_one('users', {
            'name': user_id
        }, {
            'password_hash': password_hash
        })

    @defer.inlineCallbacks
    def user_delete_access_tokens(self, user_id):
        yield self.runInteraction(
            "user_delete_access_tokens",
            self._user_delete_access_tokens, user_id
        )

    def _user_delete_access_tokens(self, txn, user_id):
        txn.execute(
            "DELETE FROM access_tokens WHERE user_id = ?",
            (user_id, )
        )

    @defer.inlineCallbacks
    def flush_user(self, user_id):
        rows = yield self._execute(
            'flush_user', None,
            "SELECT token FROM access_tokens WHERE user_id = ?",
            user_id
        )
        for r in rows:
            self.get_user_by_access_token.invalidate((r,))

    @cached()
    def get_user_by_access_token(self, token):
        """Get a user from the given access token.

        Args:
            token (str): The access token of a user.
        Returns:
            dict: Including the name (user_id) and the ID of their access token.
        Raises:
            StoreError if no user was found.
        """
        return self.runInteraction(
            "get_user_by_access_token",
            self._query_for_auth,
            token
        )

    def exchange_refresh_token(self, refresh_token, token_generator):
        """Exchange a refresh token for a new access token and refresh token.

        Doing so invalidates the old refresh token - refresh tokens are single
        use.

        Args:
            token (str): The refresh token of a user.
            token_generator (fn: str -> str): Function which, when given a
                user ID, returns a unique refresh token for that user. This
                function must never return the same value twice.
        Returns:
            tuple of (user_id, refresh_token)
        Raises:
            StoreError if no user was found with that refresh token.
        """
        return self.runInteraction(
            "exchange_refresh_token",
            self._exchange_refresh_token,
            refresh_token,
            token_generator
        )

    def _exchange_refresh_token(self, txn, old_token, token_generator):
        sql = "SELECT user_id FROM refresh_tokens WHERE token = ?"
        txn.execute(sql, (old_token,))
        rows = self.cursor_to_dict(txn)
        if not rows:
            raise StoreError(403, "Did not recognize refresh token")
        user_id = rows[0]["user_id"]

        # TODO(danielwh): Maybe perform a validation on the macaroon that
        # macaroon.user_id == user_id.

        new_token = token_generator(user_id)
        sql = "UPDATE refresh_tokens SET token = ? WHERE token = ?"
        txn.execute(sql, (new_token, old_token,))

        return user_id, new_token

    @defer.inlineCallbacks
    def is_server_admin(self, user):
        res = yield self._simple_select_one_onecol(
            table="users",
            keyvalues={"name": user.to_string()},
            retcol="admin",
            allow_none=True,
            desc="is_server_admin",
        )

        defer.returnValue(res if res else False)

    def _query_for_auth(self, txn, token):
        sql = (
            "SELECT users.name, access_tokens.id as token_id"
            " FROM users"
            " INNER JOIN access_tokens on users.name = access_tokens.user_id"
            " WHERE token = ?"
        )

        txn.execute(sql, (token,))
        rows = self.cursor_to_dict(txn)
        if rows:
            return rows[0]

        return None

    @defer.inlineCallbacks
    def user_add_threepid(self, user_id, medium, address, validated_at, added_at):
        yield self._simple_upsert("user_threepids", {
            "medium": medium,
            "address": address,
        }, {
            "user_id": user_id,
            "validated_at": validated_at,
            "added_at": added_at,
        })

    @defer.inlineCallbacks
    def user_get_threepids(self, user_id):
        ret = yield self._simple_select_list(
            "user_threepids", {
                "user_id": user_id
            },
            ['medium', 'address', 'validated_at', 'added_at'],
            'user_get_threepids'
        )
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_user_id_by_threepid(self, medium, address):
        ret = yield self._simple_select_one(
            "user_threepids",
            {
                "medium": medium,
                "address": address
            },
            ['user_id'], True, 'get_user_id_by_threepid'
        )
        if ret:
            defer.returnValue(ret['user_id'])
        defer.returnValue(None)

    @defer.inlineCallbacks
    def count_all_users(self):
        """Counts all users registered on the homeserver."""
        def _count_users(txn):
            txn.execute("SELECT COUNT(*) AS users FROM users")
            rows = self.cursor_to_dict(txn)
            if rows:
                return rows[0]["users"]
            return 0

        ret = yield self.runInteraction("count_users", _count_users)
        defer.returnValue(ret)

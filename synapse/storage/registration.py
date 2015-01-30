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

from sqlite3 import IntegrityError

from synapse.api.errors import StoreError, Codes

from ._base import SQLBaseStore


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
        row = yield self._simple_select_one("users", {"name": user_id}, ["id"])
        if not row:
            raise StoreError(400, "Bad user ID supplied.")
        row_id = row["id"]
        yield self._simple_insert(
            "access_tokens",
            {
                "user_id": row_id,
                "token": token
            }
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

        try:
            txn.execute("INSERT INTO users(name, password_hash, creation_ts) "
                        "VALUES (?,?,?)",
                        [user_id, password_hash, now])
        except IntegrityError:
            raise StoreError(
                400, "User ID already taken.", errcode=Codes.USER_IN_USE
            )

        # it's possible for this to get a conflict, but only for a single user
        # since tokens are namespaced based on their user ID
        txn.execute("INSERT INTO access_tokens(user_id, token) " +
                    "VALUES (?,?)", [txn.lastrowid, token])

    def get_user_by_id(self, user_id):
        query = ("SELECT users.name, users.password_hash FROM users"
                 " WHERE users.name = ?")
        return self._execute(
            self.cursor_to_dict,
            query, user_id
        )

    def get_user_by_token(self, token):
        """Get a user from the given access token.

        Args:
            token (str): The access token of a user.
        Returns:
            dict: Including the name (user_id), device_id and whether they are
                an admin.
        Raises:
            StoreError if no user was found.
        """
        return self.runInteraction(
            "get_user_by_token",
            self._query_for_auth,
            token
        )

    @defer.inlineCallbacks
    def is_server_admin(self, user):
        res = yield self._simple_select_one_onecol(
            table="users",
            keyvalues={"name": user.to_string()},
            retcol="admin",
            allow_none=True,
        )

        defer.returnValue(res if res else False)

    def _query_for_auth(self, txn, token):
        sql = (
            "SELECT users.name, users.admin,"
            " access_tokens.device_id, access_tokens.id as token_id"
            " FROM users"
            " INNER JOIN access_tokens on users.id = access_tokens.user_id"
            " WHERE token = ?"
        )

        cursor = txn.execute(sql, (token,))
        rows = self.cursor_to_dict(cursor)
        if rows:
            return rows[0]

        raise StoreError(404, "Token not found.")

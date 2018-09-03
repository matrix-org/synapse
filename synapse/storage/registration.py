# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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

import re

from six.moves import range

from twisted.internet import defer

from synapse.api.errors import Codes, StoreError
from synapse.storage import background_updates
from synapse.storage._base import SQLBaseStore
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks


class RegistrationWorkerStore(SQLBaseStore):
    def __init__(self, db_conn, hs):
        super(RegistrationWorkerStore, self).__init__(db_conn, hs)

        self.config = hs.config

    @cached()
    def get_user_by_id(self, user_id):
        return self._simple_select_one(
            table="users",
            keyvalues={
                "name": user_id,
            },
            retcols=[
                "name", "password_hash", "is_guest",
                "consent_version", "consent_server_notice_sent",
                "appservice_id", "creation_ts",
            ],
            allow_none=True,
            desc="get_user_by_id",
        )

    @defer.inlineCallbacks
    def is_trial_user(self, user_id):
        """Checks if user is in the "trial" period, i.e. within the first
        N days of registration defined by `mau_trial_days` config

        Args:
            user_id (str)

        Returns:
            Deferred[bool]
        """

        info = yield self.get_user_by_id(user_id)
        if not info:
            defer.returnValue(False)

        now = self.clock.time_msec()
        trial_duration_ms = self.config.mau_trial_days * 24 * 60 * 60 * 1000
        is_trial = (now - info["creation_ts"] * 1000) < trial_duration_ms
        defer.returnValue(is_trial)

    @cached()
    def get_user_by_access_token(self, token):
        """Get a user from the given access token.

        Args:
            token (str): The access token of a user.
        Returns:
            defer.Deferred: None, if the token did not match, otherwise dict
                including the keys `name`, `is_guest`, `device_id`, `token_id`.
        """
        return self.runInteraction(
            "get_user_by_access_token",
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
            desc="is_server_admin",
        )

        defer.returnValue(res if res else False)

    def _query_for_auth(self, txn, token):
        sql = (
            "SELECT users.name, users.is_guest, access_tokens.id as token_id,"
            " access_tokens.device_id"
            " FROM users"
            " INNER JOIN access_tokens on users.name = access_tokens.user_id"
            " WHERE token = ?"
        )

        txn.execute(sql, (token,))
        rows = self.cursor_to_dict(txn)
        if rows:
            return rows[0]

        return None


class RegistrationStore(RegistrationWorkerStore,
                        background_updates.BackgroundUpdateStore):

    def __init__(self, db_conn, hs):
        super(RegistrationStore, self).__init__(db_conn, hs)

        self.clock = hs.get_clock()

        self.register_background_index_update(
            "access_tokens_device_index",
            index_name="access_tokens_device_id",
            table="access_tokens",
            columns=["user_id", "device_id"],
        )

        self.register_background_index_update(
            "users_creation_ts",
            index_name="users_creation_ts",
            table="users",
            columns=["creation_ts"],
        )

        # we no longer use refresh tokens, but it's possible that some people
        # might have a background update queued to build this index. Just
        # clear the background update.
        self.register_noop_background_update("refresh_tokens_device_index")

    @defer.inlineCallbacks
    def add_access_token_to_user(self, user_id, token, device_id=None):
        """Adds an access token for the given user.

        Args:
            user_id (str): The user ID.
            token (str): The new access token to add.
            device_id (str): ID of the device to associate with the access
               token
        Raises:
            StoreError if there was a problem adding this.
        """
        next_id = self._access_tokens_id_gen.get_next()

        yield self._simple_insert(
            "access_tokens",
            {
                "id": next_id,
                "user_id": user_id,
                "token": token,
                "device_id": device_id,
            },
            desc="add_access_token_to_user",
        )

    def register(self, user_id, token=None, password_hash=None,
                 was_guest=False, make_guest=False, appservice_id=None,
                 create_profile_with_localpart=None, admin=False):
        """Attempts to register an account.

        Args:
            user_id (str): The desired user ID to register.
            token (str): The desired access token to use for this user. If this
                is not None, the given access token is associated with the user
                id.
            password_hash (str): Optional. The password hash for this user.
            was_guest (bool): Optional. Whether this is a guest account being
                upgraded to a non-guest account.
            make_guest (boolean): True if the the new user should be guest,
                false to add a regular user account.
            appservice_id (str): The ID of the appservice registering the user.
            create_profile_with_localpart (str): Optionally create a profile for
                the given localpart.
        Raises:
            StoreError if the user_id could not be registered.
        """
        return self.runInteraction(
            "register",
            self._register,
            user_id,
            token,
            password_hash,
            was_guest,
            make_guest,
            appservice_id,
            create_profile_with_localpart,
            admin
        )

    def _register(
        self,
        txn,
        user_id,
        token,
        password_hash,
        was_guest,
        make_guest,
        appservice_id,
        create_profile_with_localpart,
        admin,
    ):
        now = int(self.clock.time())

        next_id = self._access_tokens_id_gen.get_next()

        try:
            if was_guest:
                # Ensure that the guest user actually exists
                # ``allow_none=False`` makes this raise an exception
                # if the row isn't in the database.
                self._simple_select_one_txn(
                    txn,
                    "users",
                    keyvalues={
                        "name": user_id,
                        "is_guest": 1,
                    },
                    retcols=("name",),
                    allow_none=False,
                )

                self._simple_update_one_txn(
                    txn,
                    "users",
                    keyvalues={
                        "name": user_id,
                        "is_guest": 1,
                    },
                    updatevalues={
                        "password_hash": password_hash,
                        "upgrade_ts": now,
                        "is_guest": 1 if make_guest else 0,
                        "appservice_id": appservice_id,
                        "admin": 1 if admin else 0,
                    }
                )
            else:
                self._simple_insert_txn(
                    txn,
                    "users",
                    values={
                        "name": user_id,
                        "password_hash": password_hash,
                        "creation_ts": now,
                        "is_guest": 1 if make_guest else 0,
                        "appservice_id": appservice_id,
                        "admin": 1 if admin else 0,
                    }
                )
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

        if create_profile_with_localpart:
            # set a default displayname serverside to avoid ugly race
            # between auto-joins and clients trying to set displaynames
            txn.execute(
                "INSERT INTO profiles(user_id, displayname) VALUES (?,?)",
                (create_profile_with_localpart, create_profile_with_localpart)
            )

        self._invalidate_cache_and_stream(
            txn, self.get_user_by_id, (user_id,)
        )
        txn.call_after(self.is_guest.invalidate, (user_id,))

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
            return dict(txn)

        return self.runInteraction("get_users_by_id_case_insensitive", f)

    def user_set_password_hash(self, user_id, password_hash):
        """
        NB. This does *not* evict any cache because the one use for this
            removes most of the entries subsequently anyway so it would be
            pointless. Use flush_user separately.
        """
        def user_set_password_hash_txn(txn):
            self._simple_update_one_txn(
                txn,
                'users', {
                    'name': user_id
                },
                {
                    'password_hash': password_hash
                }
            )
            self._invalidate_cache_and_stream(
                txn, self.get_user_by_id, (user_id,)
            )
        return self.runInteraction(
            "user_set_password_hash", user_set_password_hash_txn
        )

    def user_set_consent_version(self, user_id, consent_version):
        """Updates the user table to record privacy policy consent

        Args:
            user_id (str): full mxid of the user to update
            consent_version (str): version of the policy the user has consented
                to

        Raises:
            StoreError(404) if user not found
        """
        def f(txn):
            self._simple_update_one_txn(
                txn,
                table='users',
                keyvalues={'name': user_id, },
                updatevalues={'consent_version': consent_version, },
            )
            self._invalidate_cache_and_stream(
                txn, self.get_user_by_id, (user_id,)
            )
        return self.runInteraction("user_set_consent_version", f)

    def user_set_consent_server_notice_sent(self, user_id, consent_version):
        """Updates the user table to record that we have sent the user a server
        notice about privacy policy consent

        Args:
            user_id (str): full mxid of the user to update
            consent_version (str): version of the policy we have notified the
                user about

        Raises:
            StoreError(404) if user not found
        """
        def f(txn):
            self._simple_update_one_txn(
                txn,
                table='users',
                keyvalues={'name': user_id, },
                updatevalues={'consent_server_notice_sent': consent_version, },
            )
            self._invalidate_cache_and_stream(
                txn, self.get_user_by_id, (user_id,)
            )
        return self.runInteraction("user_set_consent_server_notice_sent", f)

    def user_delete_access_tokens(self, user_id, except_token_id=None,
                                  device_id=None):
        """
        Invalidate access tokens belonging to a user

        Args:
            user_id (str):  ID of user the tokens belong to
            except_token_id (str): list of access_tokens IDs which should
                *not* be deleted
            device_id (str|None):  ID of device the tokens are associated with.
                If None, tokens associated with any device (or no device) will
                be deleted
        Returns:
            defer.Deferred[list[str, int, str|None, int]]: a list of
                (token, token id, device id) for each of the deleted tokens
        """
        def f(txn):
            keyvalues = {
                "user_id": user_id,
            }
            if device_id is not None:
                keyvalues["device_id"] = device_id

            items = keyvalues.items()
            where_clause = " AND ".join(k + " = ?" for k, _ in items)
            values = [v for _, v in items]
            if except_token_id:
                where_clause += " AND id != ?"
                values.append(except_token_id)

            txn.execute(
                "SELECT token, id, device_id FROM access_tokens WHERE %s" % where_clause,
                values
            )
            tokens_and_devices = [(r[0], r[1], r[2]) for r in txn]

            for token, _, _ in tokens_and_devices:
                self._invalidate_cache_and_stream(
                    txn, self.get_user_by_access_token, (token,)
                )

            txn.execute(
                "DELETE FROM access_tokens WHERE %s" % where_clause,
                values
            )

            return tokens_and_devices

        return self.runInteraction(
            "user_delete_access_tokens", f,
        )

    def delete_access_token(self, access_token):
        def f(txn):
            self._simple_delete_one_txn(
                txn,
                table="access_tokens",
                keyvalues={
                    "token": access_token
                },
            )

            self._invalidate_cache_and_stream(
                txn, self.get_user_by_access_token, (access_token,)
            )

        return self.runInteraction("delete_access_token", f)

    @cachedInlineCallbacks()
    def is_guest(self, user_id):
        res = yield self._simple_select_one_onecol(
            table="users",
            keyvalues={"name": user_id},
            retcol="is_guest",
            allow_none=True,
            desc="is_guest",
        )

        defer.returnValue(res if res else False)

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

    def user_delete_threepid(self, user_id, medium, address):
        return self._simple_delete(
            "user_threepids",
            keyvalues={
                "user_id": user_id,
                "medium": medium,
                "address": address,
            },
            desc="user_delete_threepids",
        )

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

    def count_daily_user_type(self):
        """
        Counts 1) native non guest users
               2) native guests users
               3) bridged users
        who registered on the homeserver in the past 24 hours
        """
        def _count_daily_user_type(txn):
            yesterday = int(self._clock.time()) - (60 * 60 * 24)

            sql = """
                SELECT user_type, COALESCE(count(*), 0) AS count FROM (
                    SELECT
                    CASE
                        WHEN is_guest=0 AND appservice_id IS NULL THEN 'native'
                        WHEN is_guest=1 AND appservice_id IS NULL THEN 'guest'
                        WHEN is_guest=0 AND appservice_id IS NOT NULL THEN 'bridged'
                    END AS user_type
                    FROM users
                    WHERE creation_ts > ?
                ) AS t GROUP BY user_type
            """
            results = {'native': 0, 'guest': 0, 'bridged': 0}
            txn.execute(sql, (yesterday,))
            for row in txn:
                results[row[0]] = row[1]
            return results
        return self.runInteraction("count_daily_user_type", _count_daily_user_type)

    @defer.inlineCallbacks
    def count_nonbridged_users(self):
        def _count_users(txn):
            txn.execute("""
                SELECT COALESCE(COUNT(*), 0) FROM users
                WHERE appservice_id IS NULL
            """)
            count, = txn.fetchone()
            return count

        ret = yield self.runInteraction("count_users", _count_users)
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def find_next_generated_user_id_localpart(self):
        """
        Gets the localpart of the next generated user ID.

        Generated user IDs are integers, and we aim for them to be as small as
        we can. Unfortunately, it's possible some of them are already taken by
        existing users, and there may be gaps in the already taken range. This
        function returns the start of the first allocatable gap. This is to
        avoid the case of ID 10000000 being pre-allocated, so us wasting the
        first (and shortest) many generated user IDs.
        """
        def _find_next_generated_user_id(txn):
            txn.execute("SELECT name FROM users")

            regex = re.compile("^@(\d+):")

            found = set()

            for user_id, in txn:
                match = regex.search(user_id)
                if match:
                    found.add(int(match.group(1)))
            for i in range(len(found) + 1):
                if i not in found:
                    return i

        defer.returnValue((yield self.runInteraction(
            "find_next_generated_user_id",
            _find_next_generated_user_id
        )))

    @defer.inlineCallbacks
    def get_3pid_guest_access_token(self, medium, address):
        ret = yield self._simple_select_one(
            "threepid_guest_access_tokens",
            {
                "medium": medium,
                "address": address
            },
            ["guest_access_token"], True, 'get_3pid_guest_access_token'
        )
        if ret:
            defer.returnValue(ret["guest_access_token"])
        defer.returnValue(None)

    @defer.inlineCallbacks
    def save_or_get_3pid_guest_access_token(
            self, medium, address, access_token, inviter_user_id
    ):
        """
        Gets the 3pid's guest access token if exists, else saves access_token.

        Args:
            medium (str): Medium of the 3pid. Must be "email".
            address (str): 3pid address.
            access_token (str): The access token to persist if none is
                already persisted.
            inviter_user_id (str): User ID of the inviter.

        Returns:
            deferred str: Whichever access token is persisted at the end
            of this function call.
        """
        def insert(txn):
            txn.execute(
                "INSERT INTO threepid_guest_access_tokens "
                "(medium, address, guest_access_token, first_inviter) "
                "VALUES (?, ?, ?, ?)",
                (medium, address, access_token, inviter_user_id)
            )

        try:
            yield self.runInteraction("save_3pid_guest_access_token", insert)
            defer.returnValue(access_token)
        except self.database_engine.module.IntegrityError:
            ret = yield self.get_3pid_guest_access_token(medium, address)
            defer.returnValue(ret)

    def add_user_pending_deactivation(self, user_id):
        """
        Adds a user to the table of users who need to be parted from all the rooms they're
        in
        """
        return self._simple_insert(
            "users_pending_deactivation",
            values={
                "user_id": user_id,
            },
            desc="add_user_pending_deactivation",
        )

    def del_user_pending_deactivation(self, user_id):
        """
        Removes the given user to the table of users who need to be parted from all the
        rooms they're in, effectively marking that user as fully deactivated.
        """
        # XXX: This should be simple_delete_one but we failed to put a unique index on
        # the table, so somehow duplicate entries have ended up in it.
        return self._simple_delete(
            "users_pending_deactivation",
            keyvalues={
                "user_id": user_id,
            },
            desc="del_user_pending_deactivation",
        )

    def get_user_pending_deactivation(self):
        """
        Gets one user from the table of users waiting to be parted from all the rooms
        they're in.
        """
        return self._simple_select_one_onecol(
            "users_pending_deactivation",
            keyvalues={},
            retcol="user_id",
            allow_none=True,
            desc="get_users_pending_deactivation",
        )

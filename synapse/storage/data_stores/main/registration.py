# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import logging
import re
from typing import Optional

from six import iterkeys

from twisted.internet import defer
from twisted.internet.defer import Deferred

from synapse.api.constants import UserTypes
from synapse.api.errors import Codes, StoreError, SynapseError, ThreepidValidationError
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import Database
from synapse.types import UserID
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks

THIRTY_MINUTES_IN_MS = 30 * 60 * 1000

logger = logging.getLogger(__name__)


class RegistrationWorkerStore(SQLBaseStore):
    def __init__(self, database: Database, db_conn, hs):
        super(RegistrationWorkerStore, self).__init__(database, db_conn, hs)

        self.config = hs.config
        self.clock = hs.get_clock()

    @cached()
    def get_user_by_id(self, user_id):
        return self.db.simple_select_one(
            table="users",
            keyvalues={"name": user_id},
            retcols=[
                "name",
                "password_hash",
                "is_guest",
                "admin",
                "consent_version",
                "consent_server_notice_sent",
                "appservice_id",
                "creation_ts",
                "user_type",
                "deactivated",
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
            return False

        now = self.clock.time_msec()
        trial_duration_ms = self.config.mau_trial_days * 24 * 60 * 60 * 1000
        is_trial = (now - info["creation_ts"] * 1000) < trial_duration_ms
        return is_trial

    @cached()
    def get_user_by_access_token(self, token):
        """Get a user from the given access token.

        Args:
            token (str): The access token of a user.
        Returns:
            defer.Deferred: None, if the token did not match, otherwise dict
                including the keys `name`, `is_guest`, `device_id`, `token_id`,
                `valid_until_ms`.
        """
        return self.db.runInteraction(
            "get_user_by_access_token", self._query_for_auth, token
        )

    @cachedInlineCallbacks()
    def get_expiration_ts_for_user(self, user_id):
        """Get the expiration timestamp for the account bearing a given user ID.

        Args:
            user_id (str): The ID of the user.
        Returns:
            defer.Deferred: None, if the account has no expiration timestamp,
                otherwise int representation of the timestamp (as a number of
                milliseconds since epoch).
        """
        res = yield self.db.simple_select_one_onecol(
            table="account_validity",
            keyvalues={"user_id": user_id},
            retcol="expiration_ts_ms",
            allow_none=True,
            desc="get_expiration_ts_for_user",
        )
        return res

    @defer.inlineCallbacks
    def set_account_validity_for_user(
        self, user_id, expiration_ts, email_sent, renewal_token=None
    ):
        """Updates the account validity properties of the given account, with the
        given values.

        Args:
            user_id (str): ID of the account to update properties for.
            expiration_ts (int): New expiration date, as a timestamp in milliseconds
                since epoch.
            email_sent (bool): True means a renewal email has been sent for this
                account and there's no need to send another one for the current validity
                period.
            renewal_token (str): Renewal token the user can use to extend the validity
                of their account. Defaults to no token.
        """

        def set_account_validity_for_user_txn(txn):
            self.db.simple_update_txn(
                txn=txn,
                table="account_validity",
                keyvalues={"user_id": user_id},
                updatevalues={
                    "expiration_ts_ms": expiration_ts,
                    "email_sent": email_sent,
                    "renewal_token": renewal_token,
                },
            )
            self._invalidate_cache_and_stream(
                txn, self.get_expiration_ts_for_user, (user_id,)
            )

        yield self.db.runInteraction(
            "set_account_validity_for_user", set_account_validity_for_user_txn
        )

    @defer.inlineCallbacks
    def set_renewal_token_for_user(self, user_id, renewal_token):
        """Defines a renewal token for a given user.

        Args:
            user_id (str): ID of the user to set the renewal token for.
            renewal_token (str): Random unique string that will be used to renew the
                user's account.

        Raises:
            StoreError: The provided token is already set for another user.
        """
        yield self.db.simple_update_one(
            table="account_validity",
            keyvalues={"user_id": user_id},
            updatevalues={"renewal_token": renewal_token},
            desc="set_renewal_token_for_user",
        )

    @defer.inlineCallbacks
    def get_user_from_renewal_token(self, renewal_token):
        """Get a user ID from a renewal token.

        Args:
            renewal_token (str): The renewal token to perform the lookup with.

        Returns:
            defer.Deferred[str]: The ID of the user to which the token belongs.
        """
        res = yield self.db.simple_select_one_onecol(
            table="account_validity",
            keyvalues={"renewal_token": renewal_token},
            retcol="user_id",
            desc="get_user_from_renewal_token",
        )

        return res

    @defer.inlineCallbacks
    def get_renewal_token_for_user(self, user_id):
        """Get the renewal token associated with a given user ID.

        Args:
            user_id (str): The user ID to lookup a token for.

        Returns:
            defer.Deferred[str]: The renewal token associated with this user ID.
        """
        res = yield self.db.simple_select_one_onecol(
            table="account_validity",
            keyvalues={"user_id": user_id},
            retcol="renewal_token",
            desc="get_renewal_token_for_user",
        )

        return res

    @defer.inlineCallbacks
    def get_users_expiring_soon(self):
        """Selects users whose account will expire in the [now, now + renew_at] time
        window (see configuration for account_validity for information on what renew_at
        refers to).

        Returns:
            Deferred: Resolves to a list[dict[user_id (str), expiration_ts_ms (int)]]
        """

        def select_users_txn(txn, now_ms, renew_at):
            sql = (
                "SELECT user_id, expiration_ts_ms FROM account_validity"
                " WHERE email_sent = ? AND (expiration_ts_ms - ?) <= ?"
            )
            values = [False, now_ms, renew_at]
            txn.execute(sql, values)
            return self.db.cursor_to_dict(txn)

        res = yield self.db.runInteraction(
            "get_users_expiring_soon",
            select_users_txn,
            self.clock.time_msec(),
            self.config.account_validity.renew_at,
        )

        return res

    @defer.inlineCallbacks
    def set_renewal_mail_status(self, user_id, email_sent):
        """Sets or unsets the flag that indicates whether a renewal email has been sent
        to the user (and the user hasn't renewed their account yet).

        Args:
            user_id (str): ID of the user to set/unset the flag for.
            email_sent (bool): Flag which indicates whether a renewal email has been sent
                to this user.
        """
        yield self.db.simple_update_one(
            table="account_validity",
            keyvalues={"user_id": user_id},
            updatevalues={"email_sent": email_sent},
            desc="set_renewal_mail_status",
        )

    @defer.inlineCallbacks
    def delete_account_validity_for_user(self, user_id):
        """Deletes the entry for the given user in the account validity table, removing
        their expiration date and renewal token.

        Args:
            user_id (str): ID of the user to remove from the account validity table.
        """
        yield self.db.simple_delete_one(
            table="account_validity",
            keyvalues={"user_id": user_id},
            desc="delete_account_validity_for_user",
        )

    async def is_server_admin(self, user):
        """Determines if a user is an admin of this homeserver.

        Args:
            user (UserID): user ID of the user to test

        Returns (bool):
            true iff the user is a server admin, false otherwise.
        """
        res = await self.db.simple_select_one_onecol(
            table="users",
            keyvalues={"name": user.to_string()},
            retcol="admin",
            allow_none=True,
            desc="is_server_admin",
        )

        return bool(res) if res else False

    def set_server_admin(self, user, admin):
        """Sets whether a user is an admin of this homeserver.

        Args:
            user (UserID): user ID of the user to test
            admin (bool): true iff the user is to be a server admin,
                false otherwise.
        """

        def set_server_admin_txn(txn):
            self.db.simple_update_one_txn(
                txn, "users", {"name": user.to_string()}, {"admin": 1 if admin else 0}
            )
            self._invalidate_cache_and_stream(
                txn, self.get_user_by_id, (user.to_string(),)
            )

        return self.db.runInteraction("set_server_admin", set_server_admin_txn)

    def _query_for_auth(self, txn, token):
        sql = (
            "SELECT users.name, users.is_guest, access_tokens.id as token_id,"
            " access_tokens.device_id, access_tokens.valid_until_ms"
            " FROM users"
            " INNER JOIN access_tokens on users.name = access_tokens.user_id"
            " WHERE token = ?"
        )

        txn.execute(sql, (token,))
        rows = self.db.cursor_to_dict(txn)
        if rows:
            return rows[0]

        return None

    @cachedInlineCallbacks()
    def is_real_user(self, user_id):
        """Determines if the user is a real user, ie does not have a 'user_type'.

        Args:
            user_id (str): user id to test

        Returns:
            Deferred[bool]: True if user 'user_type' is null or empty string
        """
        res = yield self.db.runInteraction(
            "is_real_user", self.is_real_user_txn, user_id
        )
        return res

    @cached()
    def is_support_user(self, user_id):
        """Determines if the user is of type UserTypes.SUPPORT

        Args:
            user_id (str): user id to test

        Returns:
            Deferred[bool]: True if user is of type UserTypes.SUPPORT
        """
        return self.db.runInteraction(
            "is_support_user", self.is_support_user_txn, user_id
        )

    def is_real_user_txn(self, txn, user_id):
        res = self.db.simple_select_one_onecol_txn(
            txn=txn,
            table="users",
            keyvalues={"name": user_id},
            retcol="user_type",
            allow_none=True,
        )
        return res is None

    def is_support_user_txn(self, txn, user_id):
        res = self.db.simple_select_one_onecol_txn(
            txn=txn,
            table="users",
            keyvalues={"name": user_id},
            retcol="user_type",
            allow_none=True,
        )
        return True if res == UserTypes.SUPPORT else False

    def get_users_by_id_case_insensitive(self, user_id):
        """Gets users that match user_id case insensitively.
        Returns a mapping of user_id -> password_hash.
        """

        def f(txn):
            sql = "SELECT name, password_hash FROM users WHERE lower(name) = lower(?)"
            txn.execute(sql, (user_id,))
            return dict(txn)

        return self.db.runInteraction("get_users_by_id_case_insensitive", f)

    async def get_user_by_external_id(
        self, auth_provider: str, external_id: str
    ) -> str:
        """Look up a user by their external auth id

        Args:
            auth_provider: identifier for the remote auth provider
            external_id: id on that system

        Returns:
            str|None: the mxid of the user, or None if they are not known
        """
        return await self.db.simple_select_one_onecol(
            table="user_external_ids",
            keyvalues={"auth_provider": auth_provider, "external_id": external_id},
            retcol="user_id",
            allow_none=True,
            desc="get_user_by_external_id",
        )

    @defer.inlineCallbacks
    def count_all_users(self):
        """Counts all users registered on the homeserver."""

        def _count_users(txn):
            txn.execute("SELECT COUNT(*) AS users FROM users")
            rows = self.db.cursor_to_dict(txn)
            if rows:
                return rows[0]["users"]
            return 0

        ret = yield self.db.runInteraction("count_users", _count_users)
        return ret

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
            results = {"native": 0, "guest": 0, "bridged": 0}
            txn.execute(sql, (yesterday,))
            for row in txn:
                results[row[0]] = row[1]
            return results

        return self.db.runInteraction("count_daily_user_type", _count_daily_user_type)

    @defer.inlineCallbacks
    def count_nonbridged_users(self):
        def _count_users(txn):
            txn.execute(
                """
                SELECT COALESCE(COUNT(*), 0) FROM users
                WHERE appservice_id IS NULL
            """
            )
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_users", _count_users)
        return ret

    @defer.inlineCallbacks
    def count_real_users(self):
        """Counts all users without a special user_type registered on the homeserver."""

        def _count_users(txn):
            txn.execute("SELECT COUNT(*) AS users FROM users where user_type is null")
            rows = self.db.cursor_to_dict(txn)
            if rows:
                return rows[0]["users"]
            return 0

        ret = yield self.db.runInteraction("count_real_users", _count_users)
        return ret

    @defer.inlineCallbacks
    def find_next_generated_user_id_localpart(self):
        """
        Gets the localpart of the next generated user ID.

        Generated user IDs are integers, so we find the largest integer user ID
        already taken and return that plus one.
        """

        def _find_next_generated_user_id(txn):
            # We bound between '@0' and '@a' to avoid pulling the entire table
            # out.
            txn.execute("SELECT name FROM users WHERE '@0' <= name AND name < '@a'")

            regex = re.compile(r"^@(\d+):")

            max_found = 0

            for (user_id,) in txn:
                match = regex.search(user_id)
                if match:
                    max_found = max(int(match.group(1)), max_found)

            return max_found + 1

        return (
            (
                yield self.db.runInteraction(
                    "find_next_generated_user_id", _find_next_generated_user_id
                )
            )
        )

    async def get_user_id_by_threepid(self, medium: str, address: str) -> Optional[str]:
        """Returns user id from threepid

        Args:
            medium: threepid medium e.g. email
            address: threepid address e.g. me@example.com

        Returns:
            The user ID or None if no user id/threepid mapping exists
        """
        user_id = await self.db.runInteraction(
            "get_user_id_by_threepid", self.get_user_id_by_threepid_txn, medium, address
        )
        return user_id

    def get_user_id_by_threepid_txn(self, txn, medium, address):
        """Returns user id from threepid

        Args:
            txn (cursor):
            medium (str): threepid medium e.g. email
            address (str): threepid address e.g. me@example.com

        Returns:
            str|None: user id or None if no user id/threepid mapping exists
        """
        ret = self.db.simple_select_one_txn(
            txn,
            "user_threepids",
            {"medium": medium, "address": address},
            ["user_id"],
            True,
        )
        if ret:
            return ret["user_id"]
        return None

    @defer.inlineCallbacks
    def user_add_threepid(self, user_id, medium, address, validated_at, added_at):
        yield self.db.simple_upsert(
            "user_threepids",
            {"medium": medium, "address": address},
            {"user_id": user_id, "validated_at": validated_at, "added_at": added_at},
        )

    @defer.inlineCallbacks
    def user_get_threepids(self, user_id):
        ret = yield self.db.simple_select_list(
            "user_threepids",
            {"user_id": user_id},
            ["medium", "address", "validated_at", "added_at"],
            "user_get_threepids",
        )
        return ret

    def user_delete_threepid(self, user_id, medium, address):
        return self.db.simple_delete(
            "user_threepids",
            keyvalues={"user_id": user_id, "medium": medium, "address": address},
            desc="user_delete_threepid",
        )

    def user_delete_threepids(self, user_id: str):
        """Delete all threepid this user has bound

        Args:
             user_id: The user id to delete all threepids of

        """
        return self.db.simple_delete(
            "user_threepids",
            keyvalues={"user_id": user_id},
            desc="user_delete_threepids",
        )

    def add_user_bound_threepid(self, user_id, medium, address, id_server):
        """The server proxied a bind request to the given identity server on
        behalf of the given user. We need to remember this in case the user
        asks us to unbind the threepid.

        Args:
            user_id (str)
            medium (str)
            address (str)
            id_server (str)

        Returns:
            Deferred
        """
        # We need to use an upsert, in case they user had already bound the
        # threepid
        return self.db.simple_upsert(
            table="user_threepid_id_server",
            keyvalues={
                "user_id": user_id,
                "medium": medium,
                "address": address,
                "id_server": id_server,
            },
            values={},
            insertion_values={},
            desc="add_user_bound_threepid",
        )

    def user_get_bound_threepids(self, user_id):
        """Get the threepids that a user has bound to an identity server through the homeserver
        The homeserver remembers where binds to an identity server occurred. Using this
        method can retrieve those threepids.

        Args:
            user_id (str): The ID of the user to retrieve threepids for

        Returns:
            Deferred[list[dict]]: List of dictionaries containing the following:
                medium (str): The medium of the threepid (e.g "email")
                address (str): The address of the threepid (e.g "bob@example.com")
        """
        return self.db.simple_select_list(
            table="user_threepid_id_server",
            keyvalues={"user_id": user_id},
            retcols=["medium", "address"],
            desc="user_get_bound_threepids",
        )

    def remove_user_bound_threepid(self, user_id, medium, address, id_server):
        """The server proxied an unbind request to the given identity server on
        behalf of the given user, so we remove the mapping of threepid to
        identity server.

        Args:
            user_id (str)
            medium (str)
            address (str)
            id_server (str)

        Returns:
            Deferred
        """
        return self.db.simple_delete(
            table="user_threepid_id_server",
            keyvalues={
                "user_id": user_id,
                "medium": medium,
                "address": address,
                "id_server": id_server,
            },
            desc="remove_user_bound_threepid",
        )

    def get_id_servers_user_bound(self, user_id, medium, address):
        """Get the list of identity servers that the server proxied bind
        requests to for given user and threepid

        Args:
            user_id (str)
            medium (str)
            address (str)

        Returns:
            Deferred[list[str]]: Resolves to a list of identity servers
        """
        return self.db.simple_select_onecol(
            table="user_threepid_id_server",
            keyvalues={"user_id": user_id, "medium": medium, "address": address},
            retcol="id_server",
            desc="get_id_servers_user_bound",
        )

    @cachedInlineCallbacks()
    def get_user_deactivated_status(self, user_id):
        """Retrieve the value for the `deactivated` property for the provided user.

        Args:
            user_id (str): The ID of the user to retrieve the status for.

        Returns:
            defer.Deferred(bool): The requested value.
        """

        res = yield self.db.simple_select_one_onecol(
            table="users",
            keyvalues={"name": user_id},
            retcol="deactivated",
            desc="get_user_deactivated_status",
        )

        # Convert the integer into a boolean.
        return res == 1

    def get_threepid_validation_session(
        self, medium, client_secret, address=None, sid=None, validated=True
    ):
        """Gets a session_id and last_send_attempt (if available) for a
        combination of validation metadata

        Args:
            medium (str|None): The medium of the 3PID
            address (str|None): The address of the 3PID
            sid (str|None): The ID of the validation session
            client_secret (str): A unique string provided by the client to help identify this
                validation attempt
            validated (bool|None): Whether sessions should be filtered by
                whether they have been validated already or not. None to
                perform no filtering

        Returns:
            Deferred[dict|None]: A dict containing the following:
                * address - address of the 3pid
                * medium - medium of the 3pid
                * client_secret - a secret provided by the client for this validation session
                * session_id - ID of the validation session
                * send_attempt - a number serving to dedupe send attempts for this session
                * validated_at - timestamp of when this session was validated if so

                Otherwise None if a validation session is not found
        """
        if not client_secret:
            raise SynapseError(
                400, "Missing parameter: client_secret", errcode=Codes.MISSING_PARAM
            )

        keyvalues = {"client_secret": client_secret}
        if medium:
            keyvalues["medium"] = medium
        if address:
            keyvalues["address"] = address
        if sid:
            keyvalues["session_id"] = sid

        assert address or sid

        def get_threepid_validation_session_txn(txn):
            sql = """
                SELECT address, session_id, medium, client_secret,
                last_send_attempt, validated_at
                FROM threepid_validation_session WHERE %s
                """ % (
                " AND ".join("%s = ?" % k for k in iterkeys(keyvalues)),
            )

            if validated is not None:
                sql += " AND validated_at IS " + ("NOT NULL" if validated else "NULL")

            sql += " LIMIT 1"

            txn.execute(sql, list(keyvalues.values()))
            rows = self.db.cursor_to_dict(txn)
            if not rows:
                return None

            return rows[0]

        return self.db.runInteraction(
            "get_threepid_validation_session", get_threepid_validation_session_txn
        )

    def delete_threepid_session(self, session_id):
        """Removes a threepid validation session from the database. This can
        be done after validation has been performed and whatever action was
        waiting on it has been carried out

        Args:
            session_id (str): The ID of the session to delete
        """

        def delete_threepid_session_txn(txn):
            self.db.simple_delete_txn(
                txn,
                table="threepid_validation_token",
                keyvalues={"session_id": session_id},
            )
            self.db.simple_delete_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
            )

        return self.db.runInteraction(
            "delete_threepid_session", delete_threepid_session_txn
        )


class RegistrationBackgroundUpdateStore(RegistrationWorkerStore):
    def __init__(self, database: Database, db_conn, hs):
        super(RegistrationBackgroundUpdateStore, self).__init__(database, db_conn, hs)

        self.clock = hs.get_clock()
        self.config = hs.config

        self.db.updates.register_background_index_update(
            "access_tokens_device_index",
            index_name="access_tokens_device_id",
            table="access_tokens",
            columns=["user_id", "device_id"],
        )

        self.db.updates.register_background_index_update(
            "users_creation_ts",
            index_name="users_creation_ts",
            table="users",
            columns=["creation_ts"],
        )

        # we no longer use refresh tokens, but it's possible that some people
        # might have a background update queued to build this index. Just
        # clear the background update.
        self.db.updates.register_noop_background_update("refresh_tokens_device_index")

        self.db.updates.register_background_update_handler(
            "user_threepids_grandfather", self._bg_user_threepids_grandfather
        )

        self.db.updates.register_background_update_handler(
            "users_set_deactivated_flag", self._background_update_set_deactivated_flag
        )

    @defer.inlineCallbacks
    def _background_update_set_deactivated_flag(self, progress, batch_size):
        """Retrieves a list of all deactivated users and sets the 'deactivated' flag to 1
        for each of them.
        """

        last_user = progress.get("user_id", "")

        def _background_update_set_deactivated_flag_txn(txn):
            txn.execute(
                """
                SELECT
                    users.name,
                    COUNT(access_tokens.token) AS count_tokens,
                    COUNT(user_threepids.address) AS count_threepids
                FROM users
                    LEFT JOIN access_tokens ON (access_tokens.user_id = users.name)
                    LEFT JOIN user_threepids ON (user_threepids.user_id = users.name)
                WHERE (users.password_hash IS NULL OR users.password_hash = '')
                AND (users.appservice_id IS NULL OR users.appservice_id = '')
                AND users.is_guest = 0
                AND users.name > ?
                GROUP BY users.name
                ORDER BY users.name ASC
                LIMIT ?;
                """,
                (last_user, batch_size),
            )

            rows = self.db.cursor_to_dict(txn)

            if not rows:
                return True, 0

            rows_processed_nb = 0

            for user in rows:
                if not user["count_tokens"] and not user["count_threepids"]:
                    self.set_user_deactivated_status_txn(txn, user["name"], True)
                    rows_processed_nb += 1

            logger.info("Marked %d rows as deactivated", rows_processed_nb)

            self.db.updates._background_update_progress_txn(
                txn, "users_set_deactivated_flag", {"user_id": rows[-1]["name"]}
            )

            if batch_size > len(rows):
                return True, len(rows)
            else:
                return False, len(rows)

        end, nb_processed = yield self.db.runInteraction(
            "users_set_deactivated_flag", _background_update_set_deactivated_flag_txn
        )

        if end:
            yield self.db.updates._end_background_update("users_set_deactivated_flag")

        return nb_processed

    @defer.inlineCallbacks
    def _bg_user_threepids_grandfather(self, progress, batch_size):
        """We now track which identity servers a user binds their 3PID to, so
        we need to handle the case of existing bindings where we didn't track
        this.

        We do this by grandfathering in existing user threepids assuming that
        they used one of the server configured trusted identity servers.
        """
        id_servers = set(self.config.trusted_third_party_id_servers)

        def _bg_user_threepids_grandfather_txn(txn):
            sql = """
                INSERT INTO user_threepid_id_server
                    (user_id, medium, address, id_server)
                SELECT user_id, medium, address, ?
                FROM user_threepids
            """

            txn.executemany(sql, [(id_server,) for id_server in id_servers])

        if id_servers:
            yield self.db.runInteraction(
                "_bg_user_threepids_grandfather", _bg_user_threepids_grandfather_txn
            )

        yield self.db.updates._end_background_update("user_threepids_grandfather")

        return 1


class RegistrationStore(RegistrationBackgroundUpdateStore):
    def __init__(self, database: Database, db_conn, hs):
        super(RegistrationStore, self).__init__(database, db_conn, hs)

        self._account_validity = hs.config.account_validity

        if self._account_validity.enabled:
            self._clock.call_later(
                0.0,
                run_as_background_process,
                "account_validity_set_expiration_dates",
                self._set_expiration_date_when_missing,
            )

        # Create a background job for culling expired 3PID validity tokens
        def start_cull():
            # run as a background process to make sure that the database transactions
            # have a logcontext to report to
            return run_as_background_process(
                "cull_expired_threepid_validation_tokens",
                self.cull_expired_threepid_validation_tokens,
            )

        hs.get_clock().looping_call(start_cull, THIRTY_MINUTES_IN_MS)

    @defer.inlineCallbacks
    def add_access_token_to_user(self, user_id, token, device_id, valid_until_ms):
        """Adds an access token for the given user.

        Args:
            user_id (str): The user ID.
            token (str): The new access token to add.
            device_id (str): ID of the device to associate with the access
                token
            valid_until_ms (int|None): when the token is valid until. None for
                no expiry.
        Raises:
            StoreError if there was a problem adding this.
        """
        next_id = self._access_tokens_id_gen.get_next()

        yield self.db.simple_insert(
            "access_tokens",
            {
                "id": next_id,
                "user_id": user_id,
                "token": token,
                "device_id": device_id,
                "valid_until_ms": valid_until_ms,
            },
            desc="add_access_token_to_user",
        )

    def register_user(
        self,
        user_id,
        password_hash=None,
        was_guest=False,
        make_guest=False,
        appservice_id=None,
        create_profile_with_displayname=None,
        admin=False,
        user_type=None,
    ):
        """Attempts to register an account.

        Args:
            user_id (str): The desired user ID to register.
            password_hash (str|None): Optional. The password hash for this user.
            was_guest (bool): Optional. Whether this is a guest account being
                upgraded to a non-guest account.
            make_guest (boolean): True if the the new user should be guest,
                false to add a regular user account.
            appservice_id (str): The ID of the appservice registering the user.
            create_profile_with_displayname (unicode): Optionally create a profile for
                the user, setting their displayname to the given value
            admin (boolean): is an admin user?
            user_type (str|None): type of user. One of the values from
                api.constants.UserTypes, or None for a normal user.

        Raises:
            StoreError if the user_id could not be registered.

        Returns:
            Deferred
        """
        return self.db.runInteraction(
            "register_user",
            self._register_user,
            user_id,
            password_hash,
            was_guest,
            make_guest,
            appservice_id,
            create_profile_with_displayname,
            admin,
            user_type,
        )

    def _register_user(
        self,
        txn,
        user_id,
        password_hash,
        was_guest,
        make_guest,
        appservice_id,
        create_profile_with_displayname,
        admin,
        user_type,
    ):
        user_id_obj = UserID.from_string(user_id)

        now = int(self.clock.time())

        try:
            if was_guest:
                # Ensure that the guest user actually exists
                # ``allow_none=False`` makes this raise an exception
                # if the row isn't in the database.
                self.db.simple_select_one_txn(
                    txn,
                    "users",
                    keyvalues={"name": user_id, "is_guest": 1},
                    retcols=("name",),
                    allow_none=False,
                )

                self.db.simple_update_one_txn(
                    txn,
                    "users",
                    keyvalues={"name": user_id, "is_guest": 1},
                    updatevalues={
                        "password_hash": password_hash,
                        "upgrade_ts": now,
                        "is_guest": 1 if make_guest else 0,
                        "appservice_id": appservice_id,
                        "admin": 1 if admin else 0,
                        "user_type": user_type,
                    },
                )
            else:
                self.db.simple_insert_txn(
                    txn,
                    "users",
                    values={
                        "name": user_id,
                        "password_hash": password_hash,
                        "creation_ts": now,
                        "is_guest": 1 if make_guest else 0,
                        "appservice_id": appservice_id,
                        "admin": 1 if admin else 0,
                        "user_type": user_type,
                    },
                )

        except self.database_engine.module.IntegrityError:
            raise StoreError(400, "User ID already taken.", errcode=Codes.USER_IN_USE)

        if self._account_validity.enabled:
            self.set_expiration_date_for_user_txn(txn, user_id)

        if create_profile_with_displayname:
            # set a default displayname serverside to avoid ugly race
            # between auto-joins and clients trying to set displaynames
            #
            # *obviously* the 'profiles' table uses localpart for user_id
            # while everything else uses the full mxid.
            txn.execute(
                "INSERT INTO profiles(user_id, displayname) VALUES (?,?)",
                (user_id_obj.localpart, create_profile_with_displayname),
            )

        if self.hs.config.stats_enabled:
            # we create a new completed user statistics row

            # we don't strictly need current_token since this user really can't
            # have any state deltas before now (as it is a new user), but still,
            # we include it for completeness.
            current_token = self._get_max_stream_id_in_current_state_deltas_txn(txn)
            self._update_stats_delta_txn(
                txn, now, "user", user_id, {}, complete_with_stream_id=current_token
            )

        self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))
        txn.call_after(self.is_guest.invalidate, (user_id,))

    def record_user_external_id(
        self, auth_provider: str, external_id: str, user_id: str
    ) -> Deferred:
        """Record a mapping from an external user id to a mxid

        Args:
            auth_provider: identifier for the remote auth provider
            external_id: id on that system
            user_id: complete mxid that it is mapped to
        """
        return self.db.simple_insert(
            table="user_external_ids",
            values={
                "auth_provider": auth_provider,
                "external_id": external_id,
                "user_id": user_id,
            },
            desc="record_user_external_id",
        )

    def user_set_password_hash(self, user_id, password_hash):
        """
        NB. This does *not* evict any cache because the one use for this
            removes most of the entries subsequently anyway so it would be
            pointless. Use flush_user separately.
        """

        def user_set_password_hash_txn(txn):
            self.db.simple_update_one_txn(
                txn, "users", {"name": user_id}, {"password_hash": password_hash}
            )
            self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))

        return self.db.runInteraction(
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
            self.db.simple_update_one_txn(
                txn,
                table="users",
                keyvalues={"name": user_id},
                updatevalues={"consent_version": consent_version},
            )
            self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))

        return self.db.runInteraction("user_set_consent_version", f)

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
            self.db.simple_update_one_txn(
                txn,
                table="users",
                keyvalues={"name": user_id},
                updatevalues={"consent_server_notice_sent": consent_version},
            )
            self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))

        return self.db.runInteraction("user_set_consent_server_notice_sent", f)

    def user_delete_access_tokens(self, user_id, except_token_id=None, device_id=None):
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
            keyvalues = {"user_id": user_id}
            if device_id is not None:
                keyvalues["device_id"] = device_id

            items = keyvalues.items()
            where_clause = " AND ".join(k + " = ?" for k, _ in items)
            values = [v for _, v in items]
            if except_token_id:
                where_clause += " AND id != ?"
                values.append(except_token_id)

            txn.execute(
                "SELECT token, id, device_id FROM access_tokens WHERE %s"
                % where_clause,
                values,
            )
            tokens_and_devices = [(r[0], r[1], r[2]) for r in txn]

            for token, _, _ in tokens_and_devices:
                self._invalidate_cache_and_stream(
                    txn, self.get_user_by_access_token, (token,)
                )

            txn.execute("DELETE FROM access_tokens WHERE %s" % where_clause, values)

            return tokens_and_devices

        return self.db.runInteraction("user_delete_access_tokens", f)

    def delete_access_token(self, access_token):
        def f(txn):
            self.db.simple_delete_one_txn(
                txn, table="access_tokens", keyvalues={"token": access_token}
            )

            self._invalidate_cache_and_stream(
                txn, self.get_user_by_access_token, (access_token,)
            )

        return self.db.runInteraction("delete_access_token", f)

    @cachedInlineCallbacks()
    def is_guest(self, user_id):
        res = yield self.db.simple_select_one_onecol(
            table="users",
            keyvalues={"name": user_id},
            retcol="is_guest",
            allow_none=True,
            desc="is_guest",
        )

        return res if res else False

    def add_user_pending_deactivation(self, user_id):
        """
        Adds a user to the table of users who need to be parted from all the rooms they're
        in
        """
        return self.db.simple_insert(
            "users_pending_deactivation",
            values={"user_id": user_id},
            desc="add_user_pending_deactivation",
        )

    def del_user_pending_deactivation(self, user_id):
        """
        Removes the given user to the table of users who need to be parted from all the
        rooms they're in, effectively marking that user as fully deactivated.
        """
        # XXX: This should be simple_delete_one but we failed to put a unique index on
        # the table, so somehow duplicate entries have ended up in it.
        return self.db.simple_delete(
            "users_pending_deactivation",
            keyvalues={"user_id": user_id},
            desc="del_user_pending_deactivation",
        )

    def get_user_pending_deactivation(self):
        """
        Gets one user from the table of users waiting to be parted from all the rooms
        they're in.
        """
        return self.db.simple_select_one_onecol(
            "users_pending_deactivation",
            keyvalues={},
            retcol="user_id",
            allow_none=True,
            desc="get_users_pending_deactivation",
        )

    def validate_threepid_session(self, session_id, client_secret, token, current_ts):
        """Attempt to validate a threepid session using a token

        Args:
            session_id (str): The id of a validation session
            client_secret (str): A unique string provided by the client to
                help identify this validation attempt
            token (str): A validation token
            current_ts (int): The current unix time in milliseconds. Used for
                checking token expiry status

        Raises:
            ThreepidValidationError: if a matching validation token was not found or has
                expired

        Returns:
            deferred str|None: A str representing a link to redirect the user
            to if there is one.
        """

        # Insert everything into a transaction in order to run atomically
        def validate_threepid_session_txn(txn):
            row = self.db.simple_select_one_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
                retcols=["client_secret", "validated_at"],
                allow_none=True,
            )

            if not row:
                raise ThreepidValidationError(400, "Unknown session_id")
            retrieved_client_secret = row["client_secret"]
            validated_at = row["validated_at"]

            if retrieved_client_secret != client_secret:
                raise ThreepidValidationError(
                    400, "This client_secret does not match the provided session_id"
                )

            row = self.db.simple_select_one_txn(
                txn,
                table="threepid_validation_token",
                keyvalues={"session_id": session_id, "token": token},
                retcols=["expires", "next_link"],
                allow_none=True,
            )

            if not row:
                raise ThreepidValidationError(
                    400, "Validation token not found or has expired"
                )
            expires = row["expires"]
            next_link = row["next_link"]

            # If the session is already validated, no need to revalidate
            if validated_at:
                return next_link

            if expires <= current_ts:
                raise ThreepidValidationError(
                    400, "This token has expired. Please request a new one"
                )

            # Looks good. Validate the session
            self.db.simple_update_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
                updatevalues={"validated_at": self.clock.time_msec()},
            )

            return next_link

        # Return next_link if it exists
        return self.db.runInteraction(
            "validate_threepid_session_txn", validate_threepid_session_txn
        )

    def upsert_threepid_validation_session(
        self,
        medium,
        address,
        client_secret,
        send_attempt,
        session_id,
        validated_at=None,
    ):
        """Upsert a threepid validation session
        Args:
            medium (str): The medium of the 3PID
            address (str): The address of the 3PID
            client_secret (str): A unique string provided by the client to
                help identify this validation attempt
            send_attempt (int): The latest send_attempt on this session
            session_id (str): The id of this validation session
            validated_at (int|None): The unix timestamp in milliseconds of
                when the session was marked as valid
        """
        insertion_values = {
            "medium": medium,
            "address": address,
            "client_secret": client_secret,
        }

        if validated_at:
            insertion_values["validated_at"] = validated_at

        return self.db.simple_upsert(
            table="threepid_validation_session",
            keyvalues={"session_id": session_id},
            values={"last_send_attempt": send_attempt},
            insertion_values=insertion_values,
            desc="upsert_threepid_validation_session",
        )

    def start_or_continue_validation_session(
        self,
        medium,
        address,
        session_id,
        client_secret,
        send_attempt,
        next_link,
        token,
        token_expires,
    ):
        """Creates a new threepid validation session if it does not already
        exist and associates a new validation token with it

        Args:
            medium (str): The medium of the 3PID
            address (str): The address of the 3PID
            session_id (str): The id of this validation session
            client_secret (str): A unique string provided by the client to
                help identify this validation attempt
            send_attempt (int): The latest send_attempt on this session
            next_link (str|None): The link to redirect the user to upon
                successful validation
            token (str): The validation token
            token_expires (int): The timestamp for which after the token
                will no longer be valid
        """

        def start_or_continue_validation_session_txn(txn):
            # Create or update a validation session
            self.db.simple_upsert_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
                values={"last_send_attempt": send_attempt},
                insertion_values={
                    "medium": medium,
                    "address": address,
                    "client_secret": client_secret,
                },
            )

            # Create a new validation token with this session ID
            self.db.simple_insert_txn(
                txn,
                table="threepid_validation_token",
                values={
                    "session_id": session_id,
                    "token": token,
                    "next_link": next_link,
                    "expires": token_expires,
                },
            )

        return self.db.runInteraction(
            "start_or_continue_validation_session",
            start_or_continue_validation_session_txn,
        )

    def cull_expired_threepid_validation_tokens(self):
        """Remove threepid validation tokens with expiry dates that have passed"""

        def cull_expired_threepid_validation_tokens_txn(txn, ts):
            sql = """
            DELETE FROM threepid_validation_token WHERE
            expires < ?
            """
            return txn.execute(sql, (ts,))

        return self.db.runInteraction(
            "cull_expired_threepid_validation_tokens",
            cull_expired_threepid_validation_tokens_txn,
            self.clock.time_msec(),
        )

    @defer.inlineCallbacks
    def set_user_deactivated_status(self, user_id, deactivated):
        """Set the `deactivated` property for the provided user to the provided value.

        Args:
            user_id (str): The ID of the user to set the status for.
            deactivated (bool): The value to set for `deactivated`.
        """

        yield self.db.runInteraction(
            "set_user_deactivated_status",
            self.set_user_deactivated_status_txn,
            user_id,
            deactivated,
        )

    def set_user_deactivated_status_txn(self, txn, user_id, deactivated):
        self.db.simple_update_one_txn(
            txn=txn,
            table="users",
            keyvalues={"name": user_id},
            updatevalues={"deactivated": 1 if deactivated else 0},
        )
        self._invalidate_cache_and_stream(
            txn, self.get_user_deactivated_status, (user_id,)
        )

    @defer.inlineCallbacks
    def _set_expiration_date_when_missing(self):
        """
        Retrieves the list of registered users that don't have an expiration date, and
        adds an expiration date for each of them.
        """

        def select_users_with_no_expiration_date_txn(txn):
            """Retrieves the list of registered users with no expiration date from the
            database, filtering out deactivated users.
            """
            sql = (
                "SELECT users.name FROM users"
                " LEFT JOIN account_validity ON (users.name = account_validity.user_id)"
                " WHERE account_validity.user_id is NULL AND users.deactivated = 0;"
            )
            txn.execute(sql, [])

            res = self.db.cursor_to_dict(txn)
            if res:
                for user in res:
                    self.set_expiration_date_for_user_txn(
                        txn, user["name"], use_delta=True
                    )

        yield self.db.runInteraction(
            "get_users_with_no_expiration_date",
            select_users_with_no_expiration_date_txn,
        )

    def set_expiration_date_for_user_txn(self, txn, user_id, use_delta=False):
        """Sets an expiration date to the account with the given user ID.

        Args:
             user_id (str): User ID to set an expiration date for.
             use_delta (bool): If set to False, the expiration date for the user will be
                now + validity period. If set to True, this expiration date will be a
                random value in the [now + period - d ; now + period] range, d being a
                delta equal to 10% of the validity period.
        """
        now_ms = self._clock.time_msec()
        expiration_ts = now_ms + self._account_validity.period

        if use_delta:
            expiration_ts = self.rand.randrange(
                expiration_ts - self._account_validity.startup_job_max_delta,
                expiration_ts,
            )

        self.db.simple_upsert_txn(
            txn,
            "account_validity",
            keyvalues={"user_id": user_id},
            values={"expiration_ts_ms": expiration_ts, "email_sent": False},
        )

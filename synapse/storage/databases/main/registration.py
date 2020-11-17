# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019,2020 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import attr

from synapse.api.constants import UserTypes
from synapse.api.errors import Codes, StoreError, SynapseError, ThreepidValidationError
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.databases.main.stats import StatsStore
from synapse.storage.types import Connection, Cursor
from synapse.storage.util.id_generators import IdGenerator
from synapse.storage.util.sequence import build_sequence_generator
from synapse.types import UserID
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

THIRTY_MINUTES_IN_MS = 30 * 60 * 1000

logger = logging.getLogger(__name__)


@attr.s(frozen=True, slots=True)
class TokenLookupResult:
    """Result of looking up an access token.

    Attributes:
        user_id: The user that this token authenticates as
        is_guest
        shadow_banned
        token_id: The ID of the access token looked up
        device_id: The device associated with the token, if any.
        valid_until_ms: The timestamp the token expires, if any.
        token_owner: The "owner" of the token. This is either the same as the
            user, or a server admin who is logged in as the user.
    """

    user_id = attr.ib(type=str)
    is_guest = attr.ib(type=bool, default=False)
    shadow_banned = attr.ib(type=bool, default=False)
    token_id = attr.ib(type=Optional[int], default=None)
    device_id = attr.ib(type=Optional[str], default=None)
    valid_until_ms = attr.ib(type=Optional[int], default=None)
    token_owner = attr.ib(type=str)

    # Make the token owner default to the user ID, which is the common case.
    @token_owner.default
    def _default_token_owner(self):
        return self.user_id


class RegistrationWorkerStore(CacheInvalidationWorkerStore):
    def __init__(self, database: DatabasePool, db_conn: Connection, hs: "HomeServer"):
        super().__init__(database, db_conn, hs)

        self.config = hs.config

        # Note: we don't check this sequence for consistency as we'd have to
        # call `find_max_generated_user_id_localpart` each time, which is
        # expensive if there are many entries.
        self._user_id_seq = build_sequence_generator(
            database.engine, find_max_generated_user_id_localpart, "user_id_seq",
        )

        self._account_validity = hs.config.account_validity
        if hs.config.run_background_tasks and self._account_validity.enabled:
            self._clock.call_later(
                0.0, self._set_expiration_date_when_missing,
            )

        # Create a background job for culling expired 3PID validity tokens
        if hs.config.run_background_tasks:
            self._clock.looping_call(
                self.cull_expired_threepid_validation_tokens, THIRTY_MINUTES_IN_MS
            )

    @cached()
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        return await self.db_pool.simple_select_one(
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

    async def is_trial_user(self, user_id: str) -> bool:
        """Checks if user is in the "trial" period, i.e. within the first
        N days of registration defined by `mau_trial_days` config

        Args:
            user_id: The user to check for trial status.
        """

        info = await self.get_user_by_id(user_id)
        if not info:
            return False

        now = self._clock.time_msec()
        trial_duration_ms = self.config.mau_trial_days * 24 * 60 * 60 * 1000
        is_trial = (now - info["creation_ts"] * 1000) < trial_duration_ms
        return is_trial

    @cached()
    async def get_user_by_access_token(self, token: str) -> Optional[TokenLookupResult]:
        """Get a user from the given access token.

        Args:
            token: The access token of a user.
        Returns:
            None, if the token did not match, otherwise a `TokenLookupResult`
        """
        return await self.db_pool.runInteraction(
            "get_user_by_access_token", self._query_for_auth, token
        )

    @cached()
    async def get_expiration_ts_for_user(self, user_id: str) -> Optional[int]:
        """Get the expiration timestamp for the account bearing a given user ID.

        Args:
            user_id: The ID of the user.
        Returns:
            None, if the account has no expiration timestamp, otherwise int
            representation of the timestamp (as a number of milliseconds since epoch).
        """
        return await self.db_pool.simple_select_one_onecol(
            table="account_validity",
            keyvalues={"user_id": user_id},
            retcol="expiration_ts_ms",
            allow_none=True,
            desc="get_expiration_ts_for_user",
        )

    async def is_account_expired(self, user_id: str, current_ts: int) -> bool:
        """
        Returns whether an user account is expired.

        Args:
            user_id: The user's ID
            current_ts: The current timestamp

        Returns:
            Whether the user account has expired
        """
        expiration_ts = await self.get_expiration_ts_for_user(user_id)
        return expiration_ts is not None and current_ts >= expiration_ts

    async def set_account_validity_for_user(
        self,
        user_id: str,
        expiration_ts: int,
        email_sent: bool,
        renewal_token: Optional[str] = None,
    ) -> None:
        """Updates the account validity properties of the given account, with the
        given values.

        Args:
            user_id: ID of the account to update properties for.
            expiration_ts: New expiration date, as a timestamp in milliseconds
                since epoch.
            email_sent: True means a renewal email has been sent for this account
                and there's no need to send another one for the current validity
                period.
            renewal_token: Renewal token the user can use to extend the validity
                of their account. Defaults to no token.
        """

        def set_account_validity_for_user_txn(txn):
            self.db_pool.simple_update_txn(
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

        await self.db_pool.runInteraction(
            "set_account_validity_for_user", set_account_validity_for_user_txn
        )

    async def set_renewal_token_for_user(
        self, user_id: str, renewal_token: str
    ) -> None:
        """Defines a renewal token for a given user.

        Args:
            user_id: ID of the user to set the renewal token for.
            renewal_token: Random unique string that will be used to renew the
                user's account.

        Raises:
            StoreError: The provided token is already set for another user.
        """
        await self.db_pool.simple_update_one(
            table="account_validity",
            keyvalues={"user_id": user_id},
            updatevalues={"renewal_token": renewal_token},
            desc="set_renewal_token_for_user",
        )

    async def get_user_from_renewal_token(self, renewal_token: str) -> str:
        """Get a user ID from a renewal token.

        Args:
            renewal_token: The renewal token to perform the lookup with.

        Returns:
            The ID of the user to which the token belongs.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="account_validity",
            keyvalues={"renewal_token": renewal_token},
            retcol="user_id",
            desc="get_user_from_renewal_token",
        )

    async def get_renewal_token_for_user(self, user_id: str) -> str:
        """Get the renewal token associated with a given user ID.

        Args:
            user_id: The user ID to lookup a token for.

        Returns:
            The renewal token associated with this user ID.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="account_validity",
            keyvalues={"user_id": user_id},
            retcol="renewal_token",
            desc="get_renewal_token_for_user",
        )

    async def get_users_expiring_soon(self) -> List[Dict[str, Any]]:
        """Selects users whose account will expire in the [now, now + renew_at] time
        window (see configuration for account_validity for information on what renew_at
        refers to).

        Returns:
            A list of dictionaries, each with a user ID and expiration time (in milliseconds).
        """

        def select_users_txn(txn, now_ms, renew_at):
            sql = (
                "SELECT user_id, expiration_ts_ms FROM account_validity"
                " WHERE email_sent = ? AND (expiration_ts_ms - ?) <= ?"
            )
            values = [False, now_ms, renew_at]
            txn.execute(sql, values)
            return self.db_pool.cursor_to_dict(txn)

        return await self.db_pool.runInteraction(
            "get_users_expiring_soon",
            select_users_txn,
            self._clock.time_msec(),
            self.config.account_validity.renew_at,
        )

    async def set_renewal_mail_status(self, user_id: str, email_sent: bool) -> None:
        """Sets or unsets the flag that indicates whether a renewal email has been sent
        to the user (and the user hasn't renewed their account yet).

        Args:
            user_id: ID of the user to set/unset the flag for.
            email_sent: Flag which indicates whether a renewal email has been sent
                to this user.
        """
        await self.db_pool.simple_update_one(
            table="account_validity",
            keyvalues={"user_id": user_id},
            updatevalues={"email_sent": email_sent},
            desc="set_renewal_mail_status",
        )

    async def delete_account_validity_for_user(self, user_id: str) -> None:
        """Deletes the entry for the given user in the account validity table, removing
        their expiration date and renewal token.

        Args:
            user_id: ID of the user to remove from the account validity table.
        """
        await self.db_pool.simple_delete_one(
            table="account_validity",
            keyvalues={"user_id": user_id},
            desc="delete_account_validity_for_user",
        )

    async def is_server_admin(self, user: UserID) -> bool:
        """Determines if a user is an admin of this homeserver.

        Args:
            user: user ID of the user to test

        Returns:
            true iff the user is a server admin, false otherwise.
        """
        res = await self.db_pool.simple_select_one_onecol(
            table="users",
            keyvalues={"name": user.to_string()},
            retcol="admin",
            allow_none=True,
            desc="is_server_admin",
        )

        return bool(res) if res else False

    async def set_server_admin(self, user: UserID, admin: bool) -> None:
        """Sets whether a user is an admin of this homeserver.

        Args:
            user: user ID of the user to test
            admin: true iff the user is to be a server admin, false otherwise.
        """

        def set_server_admin_txn(txn):
            self.db_pool.simple_update_one_txn(
                txn, "users", {"name": user.to_string()}, {"admin": 1 if admin else 0}
            )
            self._invalidate_cache_and_stream(
                txn, self.get_user_by_id, (user.to_string(),)
            )

        await self.db_pool.runInteraction("set_server_admin", set_server_admin_txn)

    def _query_for_auth(self, txn, token: str) -> Optional[TokenLookupResult]:
        sql = """
            SELECT users.name as user_id,
                users.is_guest,
                users.shadow_banned,
                access_tokens.id as token_id,
                access_tokens.device_id,
                access_tokens.valid_until_ms,
                access_tokens.user_id as token_owner
            FROM users
            INNER JOIN access_tokens on users.name = COALESCE(puppets_user_id, access_tokens.user_id)
            WHERE token = ?
        """

        txn.execute(sql, (token,))
        rows = self.db_pool.cursor_to_dict(txn)
        if rows:
            return TokenLookupResult(**rows[0])

        return None

    @cached()
    async def is_real_user(self, user_id: str) -> bool:
        """Determines if the user is a real user, ie does not have a 'user_type'.

        Args:
            user_id: user id to test

        Returns:
            True if user 'user_type' is null or empty string
        """
        return await self.db_pool.runInteraction(
            "is_real_user", self.is_real_user_txn, user_id
        )

    @cached()
    async def is_support_user(self, user_id: str) -> bool:
        """Determines if the user is of type UserTypes.SUPPORT

        Args:
            user_id: user id to test

        Returns:
            True if user is of type UserTypes.SUPPORT
        """
        return await self.db_pool.runInteraction(
            "is_support_user", self.is_support_user_txn, user_id
        )

    def is_real_user_txn(self, txn, user_id):
        res = self.db_pool.simple_select_one_onecol_txn(
            txn=txn,
            table="users",
            keyvalues={"name": user_id},
            retcol="user_type",
            allow_none=True,
        )
        return res is None

    def is_support_user_txn(self, txn, user_id):
        res = self.db_pool.simple_select_one_onecol_txn(
            txn=txn,
            table="users",
            keyvalues={"name": user_id},
            retcol="user_type",
            allow_none=True,
        )
        return True if res == UserTypes.SUPPORT else False

    async def get_users_by_id_case_insensitive(self, user_id: str) -> Dict[str, str]:
        """Gets users that match user_id case insensitively.

        Returns:
             A mapping of user_id -> password_hash.
        """

        def f(txn):
            sql = "SELECT name, password_hash FROM users WHERE lower(name) = lower(?)"
            txn.execute(sql, (user_id,))
            return dict(txn)

        return await self.db_pool.runInteraction("get_users_by_id_case_insensitive", f)

    async def get_user_by_external_id(
        self, auth_provider: str, external_id: str
    ) -> Optional[str]:
        """Look up a user by their external auth id

        Args:
            auth_provider: identifier for the remote auth provider
            external_id: id on that system

        Returns:
            the mxid of the user, or None if they are not known
        """
        return await self.db_pool.simple_select_one_onecol(
            table="user_external_ids",
            keyvalues={"auth_provider": auth_provider, "external_id": external_id},
            retcol="user_id",
            allow_none=True,
            desc="get_user_by_external_id",
        )

    async def count_all_users(self):
        """Counts all users registered on the homeserver."""

        def _count_users(txn):
            txn.execute("SELECT COUNT(*) AS users FROM users")
            rows = self.db_pool.cursor_to_dict(txn)
            if rows:
                return rows[0]["users"]
            return 0

        return await self.db_pool.runInteraction("count_users", _count_users)

    async def count_daily_user_type(self) -> Dict[str, int]:
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

        return await self.db_pool.runInteraction(
            "count_daily_user_type", _count_daily_user_type
        )

    async def count_nonbridged_users(self):
        def _count_users(txn):
            txn.execute(
                """
                SELECT COALESCE(COUNT(*), 0) FROM users
                WHERE appservice_id IS NULL
            """
            )
            (count,) = txn.fetchone()
            return count

        return await self.db_pool.runInteraction("count_users", _count_users)

    async def count_real_users(self):
        """Counts all users without a special user_type registered on the homeserver."""

        def _count_users(txn):
            txn.execute("SELECT COUNT(*) AS users FROM users where user_type is null")
            rows = self.db_pool.cursor_to_dict(txn)
            if rows:
                return rows[0]["users"]
            return 0

        return await self.db_pool.runInteraction("count_real_users", _count_users)

    async def generate_user_id(self) -> str:
        """Generate a suitable localpart for a guest user

        Returns: a (hopefully) free localpart
        """
        next_id = await self.db_pool.runInteraction(
            "generate_user_id", self._user_id_seq.get_next_id_txn
        )

        return str(next_id)

    async def get_user_id_by_threepid(self, medium: str, address: str) -> Optional[str]:
        """Returns user id from threepid

        Args:
            medium: threepid medium e.g. email
            address: threepid address e.g. me@example.com

        Returns:
            The user ID or None if no user id/threepid mapping exists
        """
        user_id = await self.db_pool.runInteraction(
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
        ret = self.db_pool.simple_select_one_txn(
            txn,
            "user_threepids",
            {"medium": medium, "address": address},
            ["user_id"],
            True,
        )
        if ret:
            return ret["user_id"]
        return None

    async def user_add_threepid(self, user_id, medium, address, validated_at, added_at):
        await self.db_pool.simple_upsert(
            "user_threepids",
            {"medium": medium, "address": address},
            {"user_id": user_id, "validated_at": validated_at, "added_at": added_at},
        )

    async def user_get_threepids(self, user_id):
        return await self.db_pool.simple_select_list(
            "user_threepids",
            {"user_id": user_id},
            ["medium", "address", "validated_at", "added_at"],
            "user_get_threepids",
        )

    async def user_delete_threepid(self, user_id, medium, address) -> None:
        await self.db_pool.simple_delete(
            "user_threepids",
            keyvalues={"user_id": user_id, "medium": medium, "address": address},
            desc="user_delete_threepid",
        )

    async def user_delete_threepids(self, user_id: str) -> None:
        """Delete all threepid this user has bound

        Args:
             user_id: The user id to delete all threepids of

        """
        await self.db_pool.simple_delete(
            "user_threepids",
            keyvalues={"user_id": user_id},
            desc="user_delete_threepids",
        )

    async def add_user_bound_threepid(
        self, user_id: str, medium: str, address: str, id_server: str
    ):
        """The server proxied a bind request to the given identity server on
        behalf of the given user. We need to remember this in case the user
        asks us to unbind the threepid.

        Args:
            user_id
            medium
            address
            id_server
        """
        # We need to use an upsert, in case they user had already bound the
        # threepid
        await self.db_pool.simple_upsert(
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

    async def user_get_bound_threepids(self, user_id: str) -> List[Dict[str, Any]]:
        """Get the threepids that a user has bound to an identity server through the homeserver
        The homeserver remembers where binds to an identity server occurred. Using this
        method can retrieve those threepids.

        Args:
            user_id: The ID of the user to retrieve threepids for

        Returns:
            List of dictionaries containing the following keys:
                medium (str): The medium of the threepid (e.g "email")
                address (str): The address of the threepid (e.g "bob@example.com")
        """
        return await self.db_pool.simple_select_list(
            table="user_threepid_id_server",
            keyvalues={"user_id": user_id},
            retcols=["medium", "address"],
            desc="user_get_bound_threepids",
        )

    async def remove_user_bound_threepid(
        self, user_id: str, medium: str, address: str, id_server: str
    ) -> None:
        """The server proxied an unbind request to the given identity server on
        behalf of the given user, so we remove the mapping of threepid to
        identity server.

        Args:
            user_id
            medium
            address
            id_server
        """
        await self.db_pool.simple_delete(
            table="user_threepid_id_server",
            keyvalues={
                "user_id": user_id,
                "medium": medium,
                "address": address,
                "id_server": id_server,
            },
            desc="remove_user_bound_threepid",
        )

    async def get_id_servers_user_bound(
        self, user_id: str, medium: str, address: str
    ) -> List[str]:
        """Get the list of identity servers that the server proxied bind
        requests to for given user and threepid

        Args:
            user_id: The user to query for identity servers.
            medium: The medium to query for identity servers.
            address: The address to query for identity servers.

        Returns:
            A list of identity servers
        """
        return await self.db_pool.simple_select_onecol(
            table="user_threepid_id_server",
            keyvalues={"user_id": user_id, "medium": medium, "address": address},
            retcol="id_server",
            desc="get_id_servers_user_bound",
        )

    @cached()
    async def get_user_deactivated_status(self, user_id: str) -> bool:
        """Retrieve the value for the `deactivated` property for the provided user.

        Args:
            user_id: The ID of the user to retrieve the status for.

        Returns:
            True if the user was deactivated, false if the user is still active.
        """

        res = await self.db_pool.simple_select_one_onecol(
            table="users",
            keyvalues={"name": user_id},
            retcol="deactivated",
            desc="get_user_deactivated_status",
        )

        # Convert the integer into a boolean.
        return res == 1

    async def get_threepid_validation_session(
        self,
        medium: Optional[str],
        client_secret: str,
        address: Optional[str] = None,
        sid: Optional[str] = None,
        validated: Optional[bool] = True,
    ) -> Optional[Dict[str, Any]]:
        """Gets a session_id and last_send_attempt (if available) for a
        combination of validation metadata

        Args:
            medium: The medium of the 3PID
            client_secret: A unique string provided by the client to help identify this
                validation attempt
            address: The address of the 3PID
            sid: The ID of the validation session
            validated: Whether sessions should be filtered by
                whether they have been validated already or not. None to
                perform no filtering

        Returns:
            A dict containing the following:
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
                " AND ".join("%s = ?" % k for k in keyvalues.keys()),
            )

            if validated is not None:
                sql += " AND validated_at IS " + ("NOT NULL" if validated else "NULL")

            sql += " LIMIT 1"

            txn.execute(sql, list(keyvalues.values()))
            rows = self.db_pool.cursor_to_dict(txn)
            if not rows:
                return None

            return rows[0]

        return await self.db_pool.runInteraction(
            "get_threepid_validation_session", get_threepid_validation_session_txn
        )

    async def delete_threepid_session(self, session_id: str) -> None:
        """Removes a threepid validation session from the database. This can
        be done after validation has been performed and whatever action was
        waiting on it has been carried out

        Args:
            session_id: The ID of the session to delete
        """

        def delete_threepid_session_txn(txn):
            self.db_pool.simple_delete_txn(
                txn,
                table="threepid_validation_token",
                keyvalues={"session_id": session_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
            )

        await self.db_pool.runInteraction(
            "delete_threepid_session", delete_threepid_session_txn
        )

    @wrap_as_background_process("cull_expired_threepid_validation_tokens")
    async def cull_expired_threepid_validation_tokens(self) -> None:
        """Remove threepid validation tokens with expiry dates that have passed"""

        def cull_expired_threepid_validation_tokens_txn(txn, ts):
            sql = """
            DELETE FROM threepid_validation_token WHERE
            expires < ?
            """
            txn.execute(sql, (ts,))

        await self.db_pool.runInteraction(
            "cull_expired_threepid_validation_tokens",
            cull_expired_threepid_validation_tokens_txn,
            self._clock.time_msec(),
        )

    @wrap_as_background_process("account_validity_set_expiration_dates")
    async def _set_expiration_date_when_missing(self):
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

            res = self.db_pool.cursor_to_dict(txn)
            if res:
                for user in res:
                    self.set_expiration_date_for_user_txn(
                        txn, user["name"], use_delta=True
                    )

        await self.db_pool.runInteraction(
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

        self.db_pool.simple_upsert_txn(
            txn,
            "account_validity",
            keyvalues={"user_id": user_id},
            values={"expiration_ts_ms": expiration_ts, "email_sent": False},
        )

    async def get_user_pending_deactivation(self) -> Optional[str]:
        """
        Gets one user from the table of users waiting to be parted from all the rooms
        they're in.
        """
        return await self.db_pool.simple_select_one_onecol(
            "users_pending_deactivation",
            keyvalues={},
            retcol="user_id",
            allow_none=True,
            desc="get_users_pending_deactivation",
        )

    async def del_user_pending_deactivation(self, user_id: str) -> None:
        """
        Removes the given user to the table of users who need to be parted from all the
        rooms they're in, effectively marking that user as fully deactivated.
        """
        # XXX: This should be simple_delete_one but we failed to put a unique index on
        # the table, so somehow duplicate entries have ended up in it.
        await self.db_pool.simple_delete(
            "users_pending_deactivation",
            keyvalues={"user_id": user_id},
            desc="del_user_pending_deactivation",
        )


class RegistrationBackgroundUpdateStore(RegistrationWorkerStore):
    def __init__(self, database: DatabasePool, db_conn: Connection, hs: "HomeServer"):
        super().__init__(database, db_conn, hs)

        self._clock = hs.get_clock()
        self.config = hs.config

        self.db_pool.updates.register_background_index_update(
            "access_tokens_device_index",
            index_name="access_tokens_device_id",
            table="access_tokens",
            columns=["user_id", "device_id"],
        )

        self.db_pool.updates.register_background_index_update(
            "users_creation_ts",
            index_name="users_creation_ts",
            table="users",
            columns=["creation_ts"],
        )

        # we no longer use refresh tokens, but it's possible that some people
        # might have a background update queued to build this index. Just
        # clear the background update.
        self.db_pool.updates.register_noop_background_update(
            "refresh_tokens_device_index"
        )

        self.db_pool.updates.register_background_update_handler(
            "user_threepids_grandfather", self._bg_user_threepids_grandfather
        )

        self.db_pool.updates.register_background_update_handler(
            "users_set_deactivated_flag", self._background_update_set_deactivated_flag
        )

    async def _background_update_set_deactivated_flag(self, progress, batch_size):
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

            rows = self.db_pool.cursor_to_dict(txn)

            if not rows:
                return True, 0

            rows_processed_nb = 0

            for user in rows:
                if not user["count_tokens"] and not user["count_threepids"]:
                    self.set_user_deactivated_status_txn(txn, user["name"], True)
                    rows_processed_nb += 1

            logger.info("Marked %d rows as deactivated", rows_processed_nb)

            self.db_pool.updates._background_update_progress_txn(
                txn, "users_set_deactivated_flag", {"user_id": rows[-1]["name"]}
            )

            if batch_size > len(rows):
                return True, len(rows)
            else:
                return False, len(rows)

        end, nb_processed = await self.db_pool.runInteraction(
            "users_set_deactivated_flag", _background_update_set_deactivated_flag_txn
        )

        if end:
            await self.db_pool.updates._end_background_update(
                "users_set_deactivated_flag"
            )

        return nb_processed

    async def _bg_user_threepids_grandfather(self, progress, batch_size):
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
            await self.db_pool.runInteraction(
                "_bg_user_threepids_grandfather", _bg_user_threepids_grandfather_txn
            )

        await self.db_pool.updates._end_background_update("user_threepids_grandfather")

        return 1

    async def set_user_deactivated_status(
        self, user_id: str, deactivated: bool
    ) -> None:
        """Set the `deactivated` property for the provided user to the provided value.

        Args:
            user_id: The ID of the user to set the status for.
            deactivated: The value to set for `deactivated`.
        """

        await self.db_pool.runInteraction(
            "set_user_deactivated_status",
            self.set_user_deactivated_status_txn,
            user_id,
            deactivated,
        )

    def set_user_deactivated_status_txn(self, txn, user_id: str, deactivated: bool):
        self.db_pool.simple_update_one_txn(
            txn=txn,
            table="users",
            keyvalues={"name": user_id},
            updatevalues={"deactivated": 1 if deactivated else 0},
        )
        self._invalidate_cache_and_stream(
            txn, self.get_user_deactivated_status, (user_id,)
        )
        txn.call_after(self.is_guest.invalidate, (user_id,))

    @cached()
    async def is_guest(self, user_id: str) -> bool:
        res = await self.db_pool.simple_select_one_onecol(
            table="users",
            keyvalues={"name": user_id},
            retcol="is_guest",
            allow_none=True,
            desc="is_guest",
        )

        return res if res else False


class RegistrationStore(StatsStore, RegistrationBackgroundUpdateStore):
    def __init__(self, database: DatabasePool, db_conn: Connection, hs: "HomeServer"):
        super().__init__(database, db_conn, hs)

        self._ignore_unknown_session_error = hs.config.request_token_inhibit_3pid_errors

        self._access_tokens_id_gen = IdGenerator(db_conn, "access_tokens", "id")

    async def add_access_token_to_user(
        self,
        user_id: str,
        token: str,
        device_id: Optional[str],
        valid_until_ms: Optional[int],
        puppets_user_id: Optional[str] = None,
    ) -> int:
        """Adds an access token for the given user.

        Args:
            user_id: The user ID.
            token: The new access token to add.
            device_id: ID of the device to associate with the access token
            valid_until_ms: when the token is valid until. None for no expiry.
        Raises:
            StoreError if there was a problem adding this.
        Returns:
            The token ID
        """
        next_id = self._access_tokens_id_gen.get_next()

        await self.db_pool.simple_insert(
            "access_tokens",
            {
                "id": next_id,
                "user_id": user_id,
                "token": token,
                "device_id": device_id,
                "valid_until_ms": valid_until_ms,
                "puppets_user_id": puppets_user_id,
            },
            desc="add_access_token_to_user",
        )

        return next_id

    def _set_device_for_access_token_txn(self, txn, token: str, device_id: str) -> str:
        old_device_id = self.db_pool.simple_select_one_onecol_txn(
            txn, "access_tokens", {"token": token}, "device_id"
        )

        self.db_pool.simple_update_txn(
            txn, "access_tokens", {"token": token}, {"device_id": device_id}
        )

        self._invalidate_cache_and_stream(txn, self.get_user_by_access_token, (token,))

        return old_device_id

    async def set_device_for_access_token(self, token: str, device_id: str) -> str:
        """Sets the device ID associated with an access token.

        Args:
            token: The access token to modify.
            device_id: The new device ID.
        Returns:
            The old device ID associated with the access token.
        """

        return await self.db_pool.runInteraction(
            "set_device_for_access_token",
            self._set_device_for_access_token_txn,
            token,
            device_id,
        )

    async def register_user(
        self,
        user_id: str,
        password_hash: Optional[str] = None,
        was_guest: bool = False,
        make_guest: bool = False,
        appservice_id: Optional[str] = None,
        create_profile_with_displayname: Optional[str] = None,
        admin: bool = False,
        user_type: Optional[str] = None,
        shadow_banned: bool = False,
    ) -> None:
        """Attempts to register an account.

        Args:
            user_id: The desired user ID to register.
            password_hash: Optional. The password hash for this user.
            was_guest: Whether this is a guest account being upgraded to a
                non-guest account.
            make_guest: True if the the new user should be guest, false to add a
                regular user account.
            appservice_id: The ID of the appservice registering the user.
            create_profile_with_displayname: Optionally create a profile for
                the user, setting their displayname to the given value
            admin: is an admin user?
            user_type: type of user. One of the values from api.constants.UserTypes,
                or None for a normal user.
            shadow_banned: Whether the user is shadow-banned, i.e. they may be
                told their requests succeeded but we ignore them.

        Raises:
            StoreError if the user_id could not be registered.
        """
        await self.db_pool.runInteraction(
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
            shadow_banned,
        )

    def _register_user(
        self,
        txn,
        user_id: str,
        password_hash: Optional[str],
        was_guest: bool,
        make_guest: bool,
        appservice_id: Optional[str],
        create_profile_with_displayname: Optional[str],
        admin: bool,
        user_type: Optional[str],
        shadow_banned: bool,
    ):
        user_id_obj = UserID.from_string(user_id)

        now = int(self._clock.time())

        try:
            if was_guest:
                # Ensure that the guest user actually exists
                # ``allow_none=False`` makes this raise an exception
                # if the row isn't in the database.
                self.db_pool.simple_select_one_txn(
                    txn,
                    "users",
                    keyvalues={"name": user_id, "is_guest": 1},
                    retcols=("name",),
                    allow_none=False,
                )

                self.db_pool.simple_update_one_txn(
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
                        "shadow_banned": shadow_banned,
                    },
                )
            else:
                self.db_pool.simple_insert_txn(
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
                        "shadow_banned": shadow_banned,
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

    async def record_user_external_id(
        self, auth_provider: str, external_id: str, user_id: str
    ) -> None:
        """Record a mapping from an external user id to a mxid

        Args:
            auth_provider: identifier for the remote auth provider
            external_id: id on that system
            user_id: complete mxid that it is mapped to
        """
        await self.db_pool.simple_insert(
            table="user_external_ids",
            values={
                "auth_provider": auth_provider,
                "external_id": external_id,
                "user_id": user_id,
            },
            desc="record_user_external_id",
        )

    async def user_set_password_hash(
        self, user_id: str, password_hash: Optional[str]
    ) -> None:
        """
        NB. This does *not* evict any cache because the one use for this
            removes most of the entries subsequently anyway so it would be
            pointless. Use flush_user separately.
        """

        def user_set_password_hash_txn(txn):
            self.db_pool.simple_update_one_txn(
                txn, "users", {"name": user_id}, {"password_hash": password_hash}
            )
            self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))

        await self.db_pool.runInteraction(
            "user_set_password_hash", user_set_password_hash_txn
        )

    async def user_set_consent_version(
        self, user_id: str, consent_version: str
    ) -> None:
        """Updates the user table to record privacy policy consent

        Args:
            user_id: full mxid of the user to update
            consent_version: version of the policy the user has consented to

        Raises:
            StoreError(404) if user not found
        """

        def f(txn):
            self.db_pool.simple_update_one_txn(
                txn,
                table="users",
                keyvalues={"name": user_id},
                updatevalues={"consent_version": consent_version},
            )
            self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))

        await self.db_pool.runInteraction("user_set_consent_version", f)

    async def user_set_consent_server_notice_sent(
        self, user_id: str, consent_version: str
    ) -> None:
        """Updates the user table to record that we have sent the user a server
        notice about privacy policy consent

        Args:
            user_id: full mxid of the user to update
            consent_version: version of the policy we have notified the user about

        Raises:
            StoreError(404) if user not found
        """

        def f(txn):
            self.db_pool.simple_update_one_txn(
                txn,
                table="users",
                keyvalues={"name": user_id},
                updatevalues={"consent_server_notice_sent": consent_version},
            )
            self._invalidate_cache_and_stream(txn, self.get_user_by_id, (user_id,))

        await self.db_pool.runInteraction("user_set_consent_server_notice_sent", f)

    async def user_delete_access_tokens(
        self,
        user_id: str,
        except_token_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> List[Tuple[str, int, Optional[str]]]:
        """
        Invalidate access tokens belonging to a user

        Args:
            user_id: ID of user the tokens belong to
            except_token_id: access_tokens ID which should *not* be deleted
            device_id: ID of device the tokens are associated with.
                If None, tokens associated with any device (or no device) will
                be deleted
        Returns:
            A tuple of (token, token id, device id) for each of the deleted tokens
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

        return await self.db_pool.runInteraction("user_delete_access_tokens", f)

    async def delete_access_token(self, access_token: str) -> None:
        def f(txn):
            self.db_pool.simple_delete_one_txn(
                txn, table="access_tokens", keyvalues={"token": access_token}
            )

            self._invalidate_cache_and_stream(
                txn, self.get_user_by_access_token, (access_token,)
            )

        await self.db_pool.runInteraction("delete_access_token", f)

    async def add_user_pending_deactivation(self, user_id: str) -> None:
        """
        Adds a user to the table of users who need to be parted from all the rooms they're
        in
        """
        await self.db_pool.simple_insert(
            "users_pending_deactivation",
            values={"user_id": user_id},
            desc="add_user_pending_deactivation",
        )

    async def validate_threepid_session(
        self, session_id: str, client_secret: str, token: str, current_ts: int
    ) -> Optional[str]:
        """Attempt to validate a threepid session using a token

        Args:
            session_id: The id of a validation session
            client_secret: A unique string provided by the client to help identify
                this validation attempt
            token: A validation token
            current_ts: The current unix time in milliseconds. Used for checking
                token expiry status

        Raises:
            ThreepidValidationError: if a matching validation token was not found or has
                expired

        Returns:
            A str representing a link to redirect the user to if there is one.
        """

        # Insert everything into a transaction in order to run atomically
        def validate_threepid_session_txn(txn):
            row = self.db_pool.simple_select_one_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
                retcols=["client_secret", "validated_at"],
                allow_none=True,
            )

            if not row:
                if self._ignore_unknown_session_error:
                    # If we need to inhibit the error caused by an incorrect session ID,
                    # use None as placeholder values for the client secret and the
                    # validation timestamp.
                    # It shouldn't be an issue because they're both only checked after
                    # the token check, which should fail. And if it doesn't for some
                    # reason, the next check is on the client secret, which is NOT NULL,
                    # so we don't have to worry about the client secret matching by
                    # accident.
                    row = {"client_secret": None, "validated_at": None}
                else:
                    raise ThreepidValidationError(400, "Unknown session_id")

            retrieved_client_secret = row["client_secret"]
            validated_at = row["validated_at"]

            row = self.db_pool.simple_select_one_txn(
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

            if retrieved_client_secret != client_secret:
                raise ThreepidValidationError(
                    400, "This client_secret does not match the provided session_id"
                )

            # If the session is already validated, no need to revalidate
            if validated_at:
                return next_link

            if expires <= current_ts:
                raise ThreepidValidationError(
                    400, "This token has expired. Please request a new one"
                )

            # Looks good. Validate the session
            self.db_pool.simple_update_txn(
                txn,
                table="threepid_validation_session",
                keyvalues={"session_id": session_id},
                updatevalues={"validated_at": self._clock.time_msec()},
            )

            return next_link

        # Return next_link if it exists
        return await self.db_pool.runInteraction(
            "validate_threepid_session_txn", validate_threepid_session_txn
        )

    async def start_or_continue_validation_session(
        self,
        medium: str,
        address: str,
        session_id: str,
        client_secret: str,
        send_attempt: int,
        next_link: Optional[str],
        token: str,
        token_expires: int,
    ) -> None:
        """Creates a new threepid validation session if it does not already
        exist and associates a new validation token with it

        Args:
            medium: The medium of the 3PID
            address: The address of the 3PID
            session_id: The id of this validation session
            client_secret: A unique string provided by the client to help
                identify this validation attempt
            send_attempt: The latest send_attempt on this session
            next_link: The link to redirect the user to upon successful validation
            token: The validation token
            token_expires: The timestamp for which after the token will no
                longer be valid
        """

        def start_or_continue_validation_session_txn(txn):
            # Create or update a validation session
            self.db_pool.simple_upsert_txn(
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
            self.db_pool.simple_insert_txn(
                txn,
                table="threepid_validation_token",
                values={
                    "session_id": session_id,
                    "token": token,
                    "next_link": next_link,
                    "expires": token_expires,
                },
            )

        await self.db_pool.runInteraction(
            "start_or_continue_validation_session",
            start_or_continue_validation_session_txn,
        )


def find_max_generated_user_id_localpart(cur: Cursor) -> int:
    """
    Gets the localpart of the max current generated user ID.

    Generated user IDs are integers, so we find the largest integer user ID
    already taken and return that.
    """

    # We bound between '@0' and '@a' to avoid pulling the entire table
    # out.
    cur.execute("SELECT name FROM users WHERE '@0' <= name AND name < '@a'")

    regex = re.compile(r"^@(\d+):")

    max_found = 0

    for (user_id,) in cur:
        match = regex.search(user_id)
        if match:
            max_found = max(int(match.group(1)), max_found)
    return max_found

# Copyright 2019 New Vector Ltd
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

import email.mime.multipart
import email.utils
import logging
from typing import TYPE_CHECKING, Awaitable, Callable, List, Optional, Tuple

from twisted.web.http import Request

from synapse.api.errors import AuthError, StoreError, SynapseError
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.types import UserID
from synapse.util import stringutils
from synapse.util.async_helpers import delay_cancellation

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# Types for callbacks to be registered via the module api
IS_USER_EXPIRED_CALLBACK = Callable[[str], Awaitable[Optional[bool]]]
ON_USER_REGISTRATION_CALLBACK = Callable[[str], Awaitable]
# Temporary hooks to allow for a transition from `/_matrix/client` endpoints
# to `/_synapse/client/account_validity`. See `register_account_validity_callbacks`.
ON_LEGACY_SEND_MAIL_CALLBACK = Callable[[str], Awaitable]
ON_LEGACY_RENEW_CALLBACK = Callable[[str], Awaitable[Tuple[bool, bool, int]]]
ON_LEGACY_ADMIN_REQUEST = Callable[[Request], Awaitable]


class AccountValidityHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.config = hs.config
        self.store = self.hs.get_datastores().main
        self.send_email_handler = self.hs.get_send_email_handler()
        self.clock = self.hs.get_clock()

        self._app_name = self.hs.config.email.email_app_name

        self._account_validity_enabled = (
            hs.config.account_validity.account_validity_enabled
        )
        self._account_validity_renew_by_email_enabled = (
            hs.config.account_validity.account_validity_renew_by_email_enabled
        )

        self._account_validity_period = None
        if self._account_validity_enabled:
            self._account_validity_period = (
                hs.config.account_validity.account_validity_period
            )

        if (
            self._account_validity_enabled
            and self._account_validity_renew_by_email_enabled
        ):
            # Don't do email-specific configuration if renewal by email is disabled.
            self._template_html = hs.config.email.account_validity_template_html
            self._template_text = hs.config.email.account_validity_template_text
            self._renew_email_subject = (
                hs.config.account_validity.account_validity_renew_email_subject
            )

            # Check the renewal emails to send and send them every 30min.
            if hs.config.worker.run_background_tasks:
                self.clock.looping_call(self._send_renewal_emails, 30 * 60 * 1000)

        self._is_user_expired_callbacks: List[IS_USER_EXPIRED_CALLBACK] = []
        self._on_user_registration_callbacks: List[ON_USER_REGISTRATION_CALLBACK] = []
        self._on_legacy_send_mail_callback: Optional[
            ON_LEGACY_SEND_MAIL_CALLBACK
        ] = None
        self._on_legacy_renew_callback: Optional[ON_LEGACY_RENEW_CALLBACK] = None

        # The legacy admin requests callback isn't a protected attribute because we need
        # to access it from the admin servlet, which is outside of this handler.
        self.on_legacy_admin_request_callback: Optional[ON_LEGACY_ADMIN_REQUEST] = None

    def register_account_validity_callbacks(
        self,
        is_user_expired: Optional[IS_USER_EXPIRED_CALLBACK] = None,
        on_user_registration: Optional[ON_USER_REGISTRATION_CALLBACK] = None,
        on_legacy_send_mail: Optional[ON_LEGACY_SEND_MAIL_CALLBACK] = None,
        on_legacy_renew: Optional[ON_LEGACY_RENEW_CALLBACK] = None,
        on_legacy_admin_request: Optional[ON_LEGACY_ADMIN_REQUEST] = None,
    ) -> None:
        """Register callbacks from module for each hook."""
        if is_user_expired is not None:
            self._is_user_expired_callbacks.append(is_user_expired)

        if on_user_registration is not None:
            self._on_user_registration_callbacks.append(on_user_registration)

        # The builtin account validity feature exposes 3 endpoints (send_mail, renew, and
        # an admin one). As part of moving the feature into a module, we need to change
        # the path from /_matrix/client/unstable/account_validity/... to
        # /_synapse/client/account_validity, because:
        #
        #   * the feature isn't part of the Matrix spec thus shouldn't live under /_matrix
        #   * the way we register servlets means that modules can't register resources
        #     under /_matrix/client
        #
        # We need to allow for a transition period between the old and new endpoints
        # in order to allow for clients to update (and for emails to be processed).
        #
        # Once the email-account-validity module is loaded, it will take control of account
        # validity by moving the rows from our `account_validity` table into its own table.
        #
        # Therefore, we need to allow modules (in practice just the one implementing the
        # email-based account validity) to temporarily hook into the legacy endpoints so we
        # can route the traffic coming into the old endpoints into the module, which is
        # why we have the following three temporary hooks.
        if on_legacy_send_mail is not None:
            if self._on_legacy_send_mail_callback is not None:
                raise RuntimeError("Tried to register on_legacy_send_mail twice")

            self._on_legacy_send_mail_callback = on_legacy_send_mail

        if on_legacy_renew is not None:
            if self._on_legacy_renew_callback is not None:
                raise RuntimeError("Tried to register on_legacy_renew twice")

            self._on_legacy_renew_callback = on_legacy_renew

        if on_legacy_admin_request is not None:
            if self.on_legacy_admin_request_callback is not None:
                raise RuntimeError("Tried to register on_legacy_admin_request twice")

            self.on_legacy_admin_request_callback = on_legacy_admin_request

    async def is_user_expired(self, user_id: str) -> bool:
        """Checks if a user has expired against third-party modules.

        Args:
            user_id: The user to check the expiry of.

        Returns:
            Whether the user has expired.
        """
        for callback in self._is_user_expired_callbacks:
            expired = await delay_cancellation(callback(user_id))
            if expired is not None:
                return expired

        if self._account_validity_enabled:
            # If no module could determine whether the user has expired and the legacy
            # configuration is enabled, fall back to it.
            return await self.store.is_account_expired(user_id, self.clock.time_msec())

        return False

    async def on_user_registration(self, user_id: str) -> None:
        """Tell third-party modules about a user's registration.

        Args:
            user_id: The ID of the newly registered user.
        """
        for callback in self._on_user_registration_callbacks:
            await callback(user_id)

    @wrap_as_background_process("send_renewals")
    async def _send_renewal_emails(self) -> None:
        """Gets the list of users whose account is expiring in the amount of time
        configured in the ``renew_at`` parameter from the ``account_validity``
        configuration, and sends renewal emails to all of these users as long as they
        have an email 3PID attached to their account.
        """
        expiring_users = await self.store.get_users_expiring_soon()

        if expiring_users:
            for user_id, expiration_ts_ms in expiring_users:
                await self._send_renewal_email(
                    user_id=user_id, expiration_ts=expiration_ts_ms
                )

    async def send_renewal_email_to_user(self, user_id: str) -> None:
        """
        Send a renewal email for a specific user.

        Args:
            user_id: The user ID to send a renewal email for.

        Raises:
            SynapseError if the user is not set to renew.
        """
        # If a module supports sending a renewal email from here, do that, otherwise do
        # the legacy dance.
        if self._on_legacy_send_mail_callback is not None:
            await self._on_legacy_send_mail_callback(user_id)
            return

        if not self._account_validity_renew_by_email_enabled:
            raise AuthError(
                403, "Account renewal via email is disabled on this server."
            )

        expiration_ts = await self.store.get_expiration_ts_for_user(user_id)

        # If this user isn't set to be expired, raise an error.
        if expiration_ts is None:
            raise SynapseError(400, "User has no expiration time: %s" % (user_id,))

        await self._send_renewal_email(user_id, expiration_ts)

    async def _send_renewal_email(self, user_id: str, expiration_ts: int) -> None:
        """Sends out a renewal email to every email address attached to the given user
        with a unique link allowing them to renew their account.

        Args:
            user_id: ID of the user to send email(s) to.
            expiration_ts: Timestamp in milliseconds for the expiration date of
                this user's account (used in the email templates).
        """
        addresses = await self._get_email_addresses_for_user(user_id)

        # Stop right here if the user doesn't have at least one email address.
        # In this case, they will have to ask their server admin to renew their
        # account manually.
        # We don't need to do a specific check to make sure the account isn't
        # deactivated, as a deactivated account isn't supposed to have any
        # email address attached to it.
        if not addresses:
            return

        try:
            user_display_name = await self.store.get_profile_displayname(
                UserID.from_string(user_id).localpart
            )
            if user_display_name is None:
                user_display_name = user_id
        except StoreError:
            user_display_name = user_id

        renewal_token = await self._get_renewal_token(user_id)
        url = "%s_matrix/client/unstable/account_validity/renew?token=%s" % (
            self.hs.config.server.public_baseurl,
            renewal_token,
        )

        template_vars = {
            "display_name": user_display_name,
            "expiration_ts": expiration_ts,
            "url": url,
        }

        html_text = self._template_html.render(**template_vars)
        plain_text = self._template_text.render(**template_vars)

        for address in addresses:
            raw_to = email.utils.parseaddr(address)[1]

            await self.send_email_handler.send_email(
                email_address=raw_to,
                subject=self._renew_email_subject,
                app_name=self._app_name,
                html=html_text,
                text=plain_text,
            )

        await self.store.set_renewal_mail_status(user_id=user_id, email_sent=True)

    async def _get_email_addresses_for_user(self, user_id: str) -> List[str]:
        """Retrieve the list of email addresses attached to a user's account.

        Args:
            user_id: ID of the user to lookup email addresses for.

        Returns:
            Email addresses for this account.
        """
        threepids = await self.store.user_get_threepids(user_id)

        addresses = []
        for threepid in threepids:
            if threepid["medium"] == "email":
                addresses.append(threepid["address"])

        return addresses

    async def _get_renewal_token(self, user_id: str) -> str:
        """Generates a 32-byte long random string that will be inserted into the
        user's renewal email's unique link, then saves it into the database.

        Args:
            user_id: ID of the user to generate a string for.

        Returns:
            The generated string.

        Raises:
            StoreError(500): Couldn't generate a unique string after 5 attempts.
        """
        attempts = 0
        while attempts < 5:
            try:
                renewal_token = stringutils.random_string(32)
                await self.store.set_renewal_token_for_user(user_id, renewal_token)
                return renewal_token
            except StoreError:
                attempts += 1
        raise StoreError(500, "Couldn't generate a unique string as refresh string.")

    async def renew_account(self, renewal_token: str) -> Tuple[bool, bool, int]:
        """Renews the account attached to a given renewal token by pushing back the
        expiration date by the current validity period in the server's configuration.

        If it turns out that the token is valid but has already been used, then the
        token is considered stale. A token is stale if the 'token_used_ts_ms' db column
        is non-null.

        This method exists to support handling the legacy account validity /renew
        endpoint. If a module implements the on_legacy_renew callback, then this process
        is delegated to the module instead.

        Args:
            renewal_token: Token sent with the renewal request.
        Returns:
            A tuple containing:
              * A bool representing whether the token is valid and unused.
              * A bool which is `True` if the token is valid, but stale.
              * An int representing the user's expiry timestamp as milliseconds since the
                epoch, or 0 if the token was invalid.
        """
        # If a module supports triggering a renew from here, do that, otherwise do the
        # legacy dance.
        if self._on_legacy_renew_callback is not None:
            return await self._on_legacy_renew_callback(renewal_token)

        try:
            (
                user_id,
                current_expiration_ts,
                token_used_ts,
            ) = await self.store.get_user_from_renewal_token(renewal_token)
        except StoreError:
            return False, False, 0

        # Check whether this token has already been used.
        if token_used_ts:
            logger.info(
                "User '%s' attempted to use previously used token '%s' to renew account",
                user_id,
                renewal_token,
            )
            return False, True, current_expiration_ts

        logger.debug("Renewing an account for user %s", user_id)

        # Renew the account. Pass the renewal_token here so that it is not cleared.
        # We want to keep the token around in case the user attempts to renew their
        # account with the same token twice (clicking the email link twice).
        #
        # In that case, the token will be accepted, but the account's expiration ts
        # will remain unchanged.
        new_expiration_ts = await self.renew_account_for_user(
            user_id, renewal_token=renewal_token
        )

        return True, False, new_expiration_ts

    async def renew_account_for_user(
        self,
        user_id: str,
        expiration_ts: Optional[int] = None,
        email_sent: bool = False,
        renewal_token: Optional[str] = None,
    ) -> int:
        """Renews the account attached to a given user by pushing back the
        expiration date by the current validity period in the server's
        configuration.

        Args:
            user_id: The ID of the user to renew.
            expiration_ts: New expiration date. Defaults to now + validity period.
            email_sent: Whether an email has been sent for this validity period.
            renewal_token: Token sent with the renewal request. The user's token
                will be cleared if this is None.

        Returns:
            New expiration date for this account, as a timestamp in
            milliseconds since epoch.
        """
        now = self.clock.time_msec()
        if expiration_ts is None:
            assert self._account_validity_period is not None
            expiration_ts = now + self._account_validity_period

        await self.store.set_account_validity_for_user(
            user_id=user_id,
            expiration_ts=expiration_ts,
            email_sent=email_sent,
            renewal_token=renewal_token,
            token_used_ts=now,
        )

        return expiration_ts

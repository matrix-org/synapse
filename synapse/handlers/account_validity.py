# -*- coding: utf-8 -*-
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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

from synapse.api.errors import StoreError
from synapse.logging.context import make_deferred_yieldable
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import UserID
from synapse.util import stringutils

logger = logging.getLogger(__name__)


class AccountValidityHandler:
    def __init__(self, hs):
        self.hs = hs
        self.config = hs.config
        self.store = self.hs.get_datastore()
        self.sendmail = self.hs.get_sendmail()
        self.clock = self.hs.get_clock()

        self._account_validity = self.hs.config.account_validity

        if (
            self._account_validity.enabled
            and self._account_validity.renew_by_email_enabled
        ):
            # Don't do email-specific configuration if renewal by email is disabled.
            self._template_html = self.config.account_validity_template_html
            self._template_text = self.config.account_validity_template_text

            try:
                app_name = self.hs.config.email_app_name

                self._subject = self._account_validity.renew_email_subject % {
                    "app": app_name
                }

                self._from_string = self.hs.config.email_notif_from % {"app": app_name}
            except Exception:
                # If substitution failed, fall back to the bare strings.
                self._subject = self._account_validity.renew_email_subject
                self._from_string = self.hs.config.email_notif_from

            self._raw_from = email.utils.parseaddr(self._from_string)[1]

            # Check the renewal emails to send and send them every 30min.
            def send_emails():
                # run as a background process to make sure that the database transactions
                # have a logcontext to report to
                return run_as_background_process(
                    "send_renewals", self._send_renewal_emails
                )

            self.clock.looping_call(send_emails, 30 * 60 * 1000)

    async def _send_renewal_emails(self):
        """Gets the list of users whose account is expiring in the amount of time
        configured in the ``renew_at`` parameter from the ``account_validity``
        configuration, and sends renewal emails to all of these users as long as they
        have an email 3PID attached to their account.
        """
        expiring_users = await self.store.get_users_expiring_soon()

        if expiring_users:
            for user in expiring_users:
                await self._send_renewal_email(
                    user_id=user["user_id"], expiration_ts=user["expiration_ts_ms"]
                )

    async def send_renewal_email_to_user(self, user_id: str):
        expiration_ts = await self.store.get_expiration_ts_for_user(user_id)
        await self._send_renewal_email(user_id, expiration_ts)

    async def _send_renewal_email(self, user_id: str, expiration_ts: int):
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
            self.hs.config.public_baseurl,
            renewal_token,
        )

        template_vars = {
            "display_name": user_display_name,
            "expiration_ts": expiration_ts,
            "url": url,
        }

        html_text = self._template_html.render(**template_vars)
        html_part = MIMEText(html_text, "html", "utf8")

        plain_text = self._template_text.render(**template_vars)
        text_part = MIMEText(plain_text, "plain", "utf8")

        for address in addresses:
            raw_to = email.utils.parseaddr(address)[1]

            multipart_msg = MIMEMultipart("alternative")
            multipart_msg["Subject"] = self._subject
            multipart_msg["From"] = self._from_string
            multipart_msg["To"] = address
            multipart_msg["Date"] = email.utils.formatdate()
            multipart_msg["Message-ID"] = email.utils.make_msgid()
            multipart_msg.attach(text_part)
            multipart_msg.attach(html_part)

            logger.info("Sending renewal email to %s", address)

            await make_deferred_yieldable(
                self.sendmail(
                    self.hs.config.email_smtp_host,
                    self._raw_from,
                    raw_to,
                    multipart_msg.as_string().encode("utf8"),
                    reactor=self.hs.get_reactor(),
                    port=self.hs.config.email_smtp_port,
                    requireAuthentication=self.hs.config.email_smtp_user is not None,
                    username=self.hs.config.email_smtp_user,
                    password=self.hs.config.email_smtp_pass,
                    requireTransportSecurity=self.hs.config.require_transport_security,
                )
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

    async def renew_account(self, renewal_token: str) -> bool:
        """Renews the account attached to a given renewal token by pushing back the
        expiration date by the current validity period in the server's configuration.

        Args:
            renewal_token: Token sent with the renewal request.
        Returns:
            Whether the provided token is valid.
        """
        try:
            user_id = await self.store.get_user_from_renewal_token(renewal_token)
        except StoreError:
            return False

        logger.debug("Renewing an account for user %s", user_id)
        await self.renew_account_for_user(user_id)

        return True

    async def renew_account_for_user(
        self, user_id: str, expiration_ts: int = None, email_sent: bool = False
    ) -> int:
        """Renews the account attached to a given user by pushing back the
        expiration date by the current validity period in the server's
        configuration.

        Args:
            renewal_token: Token sent with the renewal request.
            expiration_ts: New expiration date. Defaults to now + validity period.
            email_sen: Whether an email has been sent for this validity period.
                Defaults to False.

        Returns:
            New expiration date for this account, as a timestamp in
            milliseconds since epoch.
        """
        if expiration_ts is None:
            expiration_ts = self.clock.time_msec() + self._account_validity.period

        await self.store.set_account_validity_for_user(
            user_id=user_id, expiration_ts=expiration_ts, email_sent=email_sent
        )

        return expiration_ts

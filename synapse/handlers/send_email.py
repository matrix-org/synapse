# Copyright 2021 The Matrix.org C.I.C. Foundation
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

import email.utils
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

from synapse.logging.context import make_deferred_yieldable

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class SendEmailHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.sendmail = self.hs.get_sendmail()

    async def send_email(
        self,
        email_address: str,
        subject: str,
        app_name: str,
        html: str,
        text: str,
    ) -> None:
        """Send an email with the given information."""
        try:
            from_string = self.hs.config.email_notif_from % {"app": app_name}
        except TypeError:
            from_string = self.hs.config.email_notif_from

        raw_from = email.utils.parseaddr(from_string)[1]
        raw_to = email.utils.parseaddr(email_address)[1]

        if raw_to == "":
            raise RuntimeError("Invalid 'to' address")

        html_part = MIMEText(html, "html", "utf8")
        text_part = MIMEText(text, "plain", "utf8")

        multipart_msg = MIMEMultipart("alternative")
        multipart_msg["Subject"] = subject
        multipart_msg["From"] = from_string
        multipart_msg["To"] = email_address
        multipart_msg["Date"] = email.utils.formatdate()
        multipart_msg["Message-ID"] = email.utils.make_msgid()
        multipart_msg.attach(text_part)
        multipart_msg.attach(html_part)

        logger.info("Sending email to %s" % email_address)

        await make_deferred_yieldable(
            self.sendmail(
                self.hs.config.email_smtp_host,
                raw_from,
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

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
import inspect
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from typing import TYPE_CHECKING, Optional

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IOpenSSLContextFactory, IReactorTCP
from twisted.mail.smtp import ESMTPSender, ESMTPSenderFactory

from synapse.logging.context import make_deferred_yieldable

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class _NoTLSESMTPSender(ESMTPSender):
    """Extend ESMTPSender to disable TLS

    Unfortunatlely ESMTPSender doesn't give an easy way to disable TLS, so we override
    its internal method which it uses to generate a context factory.

    As of Twisted 21.2, one alternative is to set the `hostname` param of
    ESMTPSenderFactory to `None`, so if in future we drop support for earlier versions,
    that is a possibility.
    """

    def _getContextFactory(self) -> Optional[IOpenSSLContextFactory]:
        return None


async def _sendmail(
    reactor: IReactorTCP,
    smtphost: str,
    smtpport: int,
    from_addr: str,
    to_addr: str,
    msg_bytes: bytes,
    username: Optional[bytes] = None,
    password: Optional[bytes] = None,
    require_auth: bool = False,
    require_tls: bool = False,
    enable_tls: bool = True,
) -> None:
    """A simple wrapper around ESMTPSenderFactory, to allow substitution in tests

    Params:
        reactor: reactor to use to make the outbound connection
        smtphost: hostname to connect to
        smtpport: port to connect to
        from_addr: "From" address for email
        to_addr: "To" address for email
        msg_bytes: Message content
        username: username to authenticate with, if auth is enabled
        password: password to give when authenticating
        require_auth: if auth is not offered, fail the request
        require_tls: if TLS is not offered, fail the reqest
        enable_tls: True to enable TLS. If this is False and require_tls is True,
           the request will fail.
    """
    msg = BytesIO(msg_bytes)

    d: "Deferred[object]" = Deferred()

    # Twisted 21.2 introduced a 'hostname' parameter to ESMTPSenderFactory, which we
    # need to set to enable TLS.
    kwargs = {}
    sig = inspect.signature(ESMTPSenderFactory)
    if "hostname" in sig.parameters:
        kwargs["hostname"] = smtphost
    factory = ESMTPSenderFactory(
        username,
        password,
        from_addr,
        to_addr,
        msg,
        d,
        heloFallback=True,
        requireAuthentication=require_auth,
        requireTransportSecurity=require_tls,
        **kwargs,
    )
    if not enable_tls:
        factory.protocol = _NoTLSESMTPSender

    # the IReactorTCP interface claims host has to be a bytes, which seems to be wrong
    reactor.connectTCP(smtphost, smtpport, factory, timeout=30, bindAddress=None)  # type: ignore[arg-type]

    await make_deferred_yieldable(d)


class SendEmailHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs

        self._reactor = hs.get_reactor()

        self._from = hs.config.email.email_notif_from
        self._smtp_host = hs.config.email.email_smtp_host
        self._smtp_port = hs.config.email.email_smtp_port

        user = hs.config.email.email_smtp_user
        self._smtp_user = user.encode("utf-8") if user is not None else None
        passwd = hs.config.email.email_smtp_pass
        self._smtp_pass = passwd.encode("utf-8") if passwd is not None else None
        self._require_transport_security = hs.config.email.require_transport_security
        self._enable_tls = hs.config.email.enable_smtp_tls

        self._sendmail = _sendmail

    async def send_email(
        self,
        email_address: str,
        subject: str,
        app_name: str,
        html: str,
        text: str,
    ) -> None:
        """Send a multipart email with the given information.

        Args:
            email_address: The address to send the email to.
            subject: The email's subject.
            app_name: The app name to include in the From header.
            html: The HTML content to include in the email.
            text: The plain text content to include in the email.
        """
        try:
            from_string = self._from % {"app": app_name}
        except (KeyError, TypeError):
            from_string = self._from

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

        await self._sendmail(
            self._reactor,
            self._smtp_host,
            self._smtp_port,
            raw_from,
            raw_to,
            multipart_msg.as_string().encode("utf8"),
            username=self._smtp_user,
            password=self._smtp_pass,
            require_auth=self._smtp_user is not None,
            require_tls=self._require_transport_security,
            enable_tls=self._enable_tls,
        )

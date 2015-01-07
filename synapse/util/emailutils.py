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
""" This module allows you to send out emails.
"""
import email.utils
import smtplib
import twisted.python.log
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import logging

logger = logging.getLogger(__name__)


class EmailException(Exception):
    pass


def send_email(smtp_server, from_addr, to_addr, subject, body):
    """Sends an email.

    Args:
        smtp_server(str): The SMTP server to use.
        from_addr(str): The address to send from.
        to_addr(str): The address to send to.
        subject(str): The subject of the email.
        body(str): The plain text body of the email.
    Raises:
        EmailException if there was a problem sending the mail.
    """
    if not smtp_server or not from_addr or not to_addr:
        raise EmailException("Need SMTP server, from and to addresses. Check"
                             " the config to set these.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = to_addr
    plain_part = MIMEText(body)
    msg.attach(plain_part)

    raw_from = email.utils.parseaddr(from_addr)[1]
    raw_to = email.utils.parseaddr(to_addr)[1]
    if not raw_from or not raw_to:
        raise EmailException("Couldn't parse from/to address.")

    logger.info("Sending email to %s on server %s with subject %s",
                to_addr, smtp_server, subject)

    try:
        smtp = smtplib.SMTP(smtp_server)
        smtp.sendmail(raw_from, raw_to, msg.as_string())
        smtp.quit()
    except Exception as origException:
        twisted.python.log.err()
        ese = EmailException()
        ese.cause = origException
        raise ese

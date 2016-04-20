# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import smtplib
import email.utils
import email.mime.multipart
from email.mime.text import MIMEText


class Mailer(object):
    def __init__(self, store, smtp_host, smtp_port, notif_from):
        self.store = store
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.notif_from = notif_from

    @defer.inlineCallbacks
    def send_notification_mail(self, user_id, email_address, push_action):
        raw_from = email.utils.parseaddr(self.notif_from)[1]
        raw_to = email.utils.parseaddr(email_address)[1]

        if raw_to == '':
            raise RuntimeError("Invalid 'to' address")

        plainText = "yo dawg, you got notifications!"

        text_part = MIMEText(plainText, "plain")
        text_part['Subject'] = "New Matrix Notifications"
        text_part['From'] = self.notif_from
        text_part['To'] = email_address

        smtp = smtplib.SMTP(self.smtp_host, self.smtp_port)
        smtp.sendmail(raw_from, raw_to, text_part.as_string())
        smtp.quit()